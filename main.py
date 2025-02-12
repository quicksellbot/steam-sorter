from json import dump, load

from os.path import join, abspath, exists
from os import getcwd, startfile, mkdir, walk

from time import sleep, strftime, gmtime
from io import BytesIO, TextIOWrapper

from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog, QDialog, QMenu, QAction
from PyQt5.QtCore import Qt, QTimer, QPoint, QByteArray
from PyQt5.QtGui import QIcon, QPixmap
from pathlib import Path

from async_timeout import timeout
from pyzipper import AESZipFile
from pyzipper.zipfile import (_EndRecData, BadZipFile, _ECD_SIZE, _ECD_OFFSET, _ECD_COMMENT, _ECD_LOCATION,
                              _ECD_SIGNATURE, stringEndArchive64, sizeEndCentDir64, sizeEndCentDir64Locator,
                              sizeCentralDir, struct, structCentralDir, _CD_SIGNATURE, stringCentralDir,
                              _CD_FILENAME_LENGTH, _MASK_UTF_FILENAME, _CD_EXTRA_FIELD_LENGTH, _CD_COMMENT_LENGTH,
                              _CD_LOCAL_HEADER_OFFSET, MAX_EXTRACT_VERSION, )
# from rarfile import RarFile
from py7zr import SevenZipFile

import multiprocessing
from typing_extensions import override

import passwords_manager, searcher_new_gui

WRITER_REFRESH_TOKENS = "_REFRESH"
WRITER_HELP_STEAM_POWERED = "HELP_POWERED"
WRITER_STORE_STEAM_POWERED = "STORE_POWERED"
WRITER_COMMUNITY = "_COMMUNITY"
IMAGE_B64 = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa\x00\x00\x00\tpHYs\x00\x00\x00v\x00\x00\x00v\x01N{&\x08\x00\x00\x04\xf0iTXtXML:com.adobe.xmp\x00\x00\x00\x00\x00<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?> <x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 9.1-c002 79.a6a6396, 2024/03/12-07:48:23        "> <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"> <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#" xmp:CreatorTool="Adobe Photoshop 25.11 (Windows)" xmp:CreateDate="2024-11-12T00:13:13+03:00" xmp:ModifyDate="2024-11-12T00:15:04+03:00" xmp:MetadataDate="2024-11-12T00:15:04+03:00" dc:format="image/png" photoshop:ColorMode="3" xmpMM:InstanceID="xmp.iid:f3e91d02-1393-8840-8f2b-4e00f331b76e" xmpMM:DocumentID="xmp.did:f3e91d02-1393-8840-8f2b-4e00f331b76e" xmpMM:OriginalDocumentID="xmp.did:f3e91d02-1393-8840-8f2b-4e00f331b76e"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action="created" stEvt:instanceID="xmp.iid:f3e91d02-1393-8840-8f2b-4e00f331b76e" stEvt:when="2024-11-12T00:13:13+03:00" stEvt:softwareAgent="Adobe Photoshop 25.11 (Windows)"/> </rdf:Seq> </xmpMM:History> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end="r"?>\x94\xd2\xb5w\x00\x00\x00pIDAT8\x8d\xad\x93[\n\xc0 \x10\xc4\xa6\xbdC\xa5\xde\xff\xa0\xf1K\x10\xdd\x17\xb4\xc2\x82\xa8\x898\x8b\x92\x84$\x80\x06\xa8XmrZ&U\xc9\n#\xe0\xd9$=\x80\xf7\xb3\xaf\xb7aI\x0e\x18Pt\xa0g\xf0.\xf0$.l\t\xce\x90\x92\x90KaY7\xcf\xbaU\x1f\x97\xb9\xfa\xf7\x13\xac\xc0\xc2\x16\xa7}\xceZ\\\x81CI\x15v%\xcaB*\x84\xfc\xed;\x0f\xdd\x9f*\x07a\x06qf\x00\x00\x00\x00IEND\xaeB`\x82'


MAX_FILE_SIZE = 1024 * 1024 * 19
CHECK_SIZE = lambda string: len(string)


class AESZipFile2(AESZipFile):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @override
    def _RealGetContents(self):
        """Read in the table of contents for the ZIP file."""
        fp = self.fp
        try:
            endrec = _EndRecData(fp)
        except OSError:
            raise BadZipFile("File is not a zip file")
        if not endrec:
            raise BadZipFile("File is not a zip file")
        if self.debug > 1:
            ...#print(endrec)
        size_cd = endrec[_ECD_SIZE]             # bytes in central directory
        offset_cd = endrec[_ECD_OFFSET]         # offset of central directory
        self._comment = endrec[_ECD_COMMENT]    # archive comment

        # "concat" is zero, unless zip was concatenated to another file
        concat = endrec[_ECD_LOCATION] - size_cd - offset_cd
        if endrec[_ECD_SIGNATURE] == stringEndArchive64:
            # If Zip64 extension structures are present, account for them
            concat -= (sizeEndCentDir64 + sizeEndCentDir64Locator)

        if self.debug > 2:
            inferred = concat + offset_cd
            ...#print("given, inferred, offset", offset_cd, inferred, concat)
        # self.start_dir:  Position of start of central directory
        self.start_dir = offset_cd + concat
        fp.seek(self.start_dir, 0)
        data = fp.read(size_cd)
        fp = BytesIO(data)
        total = 0
        while total < size_cd:
            centdir = fp.read(sizeCentralDir)
            if len(centdir) != sizeCentralDir:
                raise BadZipFile("Truncated central directory")
            centdir = struct.unpack(structCentralDir, centdir)
            if centdir[_CD_SIGNATURE] != stringCentralDir:
                raise BadZipFile("Bad magic number for central directory")
            if self.debug > 2:
                ...#print(centdir)
            filename = fp.read(centdir[_CD_FILENAME_LENGTH])
            flags = centdir[5]
            if flags & _MASK_UTF_FILENAME:
                # UTF-8 file names extension
                filename = filename.decode('utf-8', errors="ignore")
            else:
                # Historical ZIP filename encoding
                filename = filename.decode('cp437')
            # Create ZipInfo instance to store file information
            x = self.zipinfo_cls(filename)
            x.extra = fp.read(centdir[_CD_EXTRA_FIELD_LENGTH])
            x.comment = fp.read(centdir[_CD_COMMENT_LENGTH])
            x.header_offset = centdir[_CD_LOCAL_HEADER_OFFSET]
            (x.create_version, x.create_system, x.extract_version, x.reserved,
             x.flag_bits, x.compress_type, t, d,
             x.CRC, x.compress_size, x.file_size) = centdir[1:12]
            if x.extract_version > MAX_EXTRACT_VERSION:
                raise NotImplementedError("zip file version %.1f" %
                                          (x.extract_version / 10))
            x.volume, x.internal_attr, x.external_attr = centdir[15:18]
            # Convert date/time code to (year, month, day, hour, min, sec)
            x._raw_time = t
            x.date_time = ((d >> 9)+1980, (d >> 5) & 0xF, d & 0x1F,
                           t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)

            x._decodeExtra()
            x.header_offset = x.header_offset + concat
            self.filelist.append(x)
            self.NameToInfo[x.filename] = x

            # update total bytes read from central directory
            total = (total + sizeCentralDir + centdir[_CD_FILENAME_LENGTH]
                     + centdir[_CD_EXTRA_FIELD_LENGTH]
                     + centdir[_CD_COMMENT_LENGTH])

            if self.debug > 2:
                ...#print("total", total)

class ProcessParser(multiprocessing.Process):
    def __init__(self, part_paths, check_archives, pwds):
        super().__init__()
        self.name = "PROCESS"
        self.pwds = pwds
        self.paths = part_paths
        self.check_archives = check_archives
        self.progressQueue = multiprocessing.Queue()
        self.result = multiprocessing.Queue()
        self.complete = multiprocessing.Value("i", 0)
        self.terminateFlag = multiprocessing.Value("i", 0)



        self.pwdnotfounds = []

    def run(self):
        try:
            steamCookies = self.getCookiesFromFiles(self.paths)
        except Exception as e:
            res = {"cookies": [], "pwderr": []}
        else:
            res = {"cookies": steamCookies, "pwderr": self.pwdnotfounds}

        self.result.put(res)
        self.complete.value = 1
        import gc
        gc.collect()
        self.terminateFlag.value = 2

    def getCookiesFromFiles(self, paths):
        steamLines = []

        for path in paths:
            if self.terminateFlag.value == 1:
                break
            if path.endswith(".txt"):
                notCookieLine = 0
                localSteamCookies = ""
                cookiesFlag = False
                try:
                    with open(path, encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.replace('\r', '').strip()
                            if len(line.split("\t")) == 7:
                                if not cookiesFlag: cookiesFlag = True
                                if ("steamLoginSecure" in line) or ("steamRefresh_steam" in line):
                                    localSteamCookies += f"{line}\n"
                            elif not cookiesFlag:
                                notCookieLine += 1
                            if notCookieLine > 100: break
                except Exception as e:
                    print(f"err {e}")
                    pass
                if localSteamCookies:
                    self.progressQueue.put(-2)
                    steamLines.append(localSteamCookies)

            elif path.endswith(".zip") and self.check_archives:
                steamLines += self.readZip(path)
            # elif path.endswith(".rar") and self.check_archives:
            #     steamLines += self.readRar(path)
            elif path.endswith(".7z") and self.check_archives:
                steamLines += self.read7zip(path)

            self.progressQueue.put(-1)

        return steamLines

    def readZip(self, archive, pwd=None):
        archiveSteamContent = []
        #print(f"opening {archive}")

        if isinstance(archive, BytesIO): archive.seek(0)
        with AESZipFile2(archive, 'r') as zip_ref:
            names = [file for file in zip_ref.namelist() if file.endswith(('.txt', ".7z", ".zip"))]
            passwordChecked = False
            for file in names:
                try:
                    with zip_ref.open(file, pwd=pwd) as extracted_file:
                        if extracted_file.read(24):
                            passwordChecked = True
                            break
                except Exception as e:
                    if 'encrypted' in str(e):
                        pwd = self.crackPassword(archive, 'zip')
                        if not pwd:
                            self.pwdnotfounds.append(zip_ref.filename)
                            return archiveSteamContent
                        else: pwd = pwd.encode('utf-8')
                        passwordChecked = True
                        break
                    else:
                        #print(f"READZIP {e}")
                        return archiveSteamContent


            if not passwordChecked:
                self.pwdnotfounds.append(zip_ref.filename)
                return archiveSteamContent

        if isinstance(archive, BytesIO): archive.seek(0)
        with AESZipFile2(archive, 'r') as zip_ref:
            #print(f"opened {archive}")
            self.progressQueue.put(len(names))

            for file in names:
                if self.terminateFlag.value == 1:
                    zip_ref.close()
                    del zip_ref
                    if isinstance(archive, BytesIO): del archive
                    raise Exception("EXIT")

                result = self.concurrencyReader(zip_ref, file, "zip", pwd)
                if result: archiveSteamContent += result
                self.progressQueue.put(-1)


        return archiveSteamContent

    def read7zip(self, archive, pwd=None):
        archiveSteamContent = []
        ...#print(f"opening {archive}")

        if isinstance(archive, BytesIO): archive.seek(0)
        with SevenZipFile(archive, 'r') as seven_zip_ref:
            if seven_zip_ref.needs_password():
                pwd = self.crackPassword(archive, '7z')
                if not pwd:
                    self.pwdnotfounds.append(seven_zip_ref.filename)
                    return archiveSteamContent

        if isinstance(archive, BytesIO): archive.seek(0)
        with SevenZipFile(archive, 'r', password=pwd) as seven_zip_ref:
            ...#print(f"opened {archive}")
            names = [file_info.filename for file_info in
                                         seven_zip_ref.list() if file_info.filename.endswith(('.txt', ".7z", ".zip"))]
            self.progressQueue.put(len(names))

            extracted_files_dict = seven_zip_ref.read(names)

            for filename, extracted_file in extracted_files_dict.items():
                if self.terminateFlag.value == 1:
                    del extracted_files_dict
                    seven_zip_ref.close()
                    del seven_zip_ref
                    if isinstance(archive, BytesIO): del archive
                    raise Exception("EXIT")

                if filename.endswith(".txt"):
                    notCookieLine = 0
                    localSteamCookies = ""
                    cookiesFlag = False

                    with TextIOWrapper(extracted_file, encoding='utf-8', errors='ignore') as text_file:
                        file_txt = text_file.read()
                    for line in file_txt.split('\n'):
                        line = line.replace('\r', '').strip()
                        if len(line.split("\t")) == 7:
                            if not cookiesFlag:
                                cookiesFlag = True
                            if "steamLoginSecure" in line or "steamRefresh_steam" in line:
                                localSteamCookies += f"{line}\n"
                        elif not cookiesFlag:
                            notCookieLine += 1
                        if notCookieLine > 100:
                            break

                    if localSteamCookies:
                        self.progressQueue.put(-2)
                        archiveSteamContent.append(localSteamCookies)

                elif filename.endswith(".zip") and self.check_archives:
                    archiveSteamContent += self.readZip(extracted_file)

                # elif filename.endswith(".rar") and self.check_archives:
                #     archiveSteamContent += self.readRar(extracted_file)

                elif filename.endswith(".7z") and self.check_archives:
                    archiveSteamContent += self.read7zip(extracted_file)


        try:
            #del extracted_file
            del extracted_files_dict
            del file_txt
        except: pass

        return archiveSteamContent

    def readRar(self, archive, pwd=None, RarFile=None):
        "DISABLED : RarFile=None(delete) for use"
        archiveSteamContent = []
        ...#print(archive)

        if isinstance(archive, BytesIO): archive.seek(0)
        with RarFile(archive, 'r') as rar_ref:
            names = [file for file in rar_ref.namelist() if file.endswith(('.txt', ".rar", ".7z", ".zip"))]
            if rar_ref.needs_password():
                pwd = self.crackPassword(archive, "rar")
                if not pwd:
                    self.pwdnotfounds.append(rar_ref.filename)
                    return archiveSteamContent

        if isinstance(archive, BytesIO): archive.seek(0)
        with RarFile(archive, 'r') as rar_ref:
            self.progressQueue.put(len(names))

            for name in names:
                try:
                    result = self.concurrencyReader(rar_ref, name, "rar", pwd)
                    if result: archiveSteamContent += result
                    self.progressQueue.put(-1)
                except Exception as e:
                    if "EXIT" in str(e):
                        try:
                            rar_ref.close()
                            del rar_ref
                            if isinstance(archive, BytesIO): del archive
                        except: pass
                        return archiveSteamContent

      #  tmprar.cleanup()
        return archiveSteamContent

    def crackPassword(self, archive, archiveType):
        pwdFinded = False

        for pwd in self.pwds:
            try:
                if isinstance(archive, BytesIO): archive.seek(0)
                if archiveType == 'rar':
                    ...
                    # with RarFile(archive, 'r') as rar_ref:
                    #     for file in rar_ref.namelist():
                    #         if file.endswith(('.txt', ".rar", ".7z", ".zip")):
                    #             with rar_ref.open(file, pwd=pwd) as extracted_file:
                    #                 data = extracted_file.read()
                    #                 if data:
                    #                     pwdFinded = True
                    #                     break

                elif archiveType == '7z':
                    with SevenZipFile(archive, 'r', password=pwd) as seven_zip_ref:
                        for i in seven_zip_ref.list():
                            if not i.is_directory:
                                data = seven_zip_ref.read([i.filename])
                                if data:
                                    pwdFinded = True
                                    break

                elif archiveType == 'zip':
                    with AESZipFile2(archive, 'r') as zip_ref:
                        for file in zip_ref.namelist():
                            if file.endswith(('.txt', ".rar", ".7z", ".zip")):
                                with zip_ref.open(file, pwd=pwd.encode('utf-8')) as extracted_file:
                                    data = extracted_file.read(24)
                                    if data:
                                        pwdFinded = True
                                        break

            except Exception as e:
                ...
            else:
                ...
            finally:
                try: del data
                except: pass

                if pwdFinded:
                    return pwd

        return None

    def concurrencyReader(self, ref, filename, archiveType, pwd=None):
        if self.terminateFlag.value == 1:
            raise Exception("EXIT")

        archiveSteamContent = []
        try:

            if archiveType == 'rar':
                ...
                # extracted_file = ref.read(filename, pwd)
                # if filename.endswith(".txt"):
                #     file_txt = extracted_file.decode(encoding='utf-8', errors="ignore")
                # else:
                #     bytesio = BytesIO(extracted_file)
            elif archiveType == '7z':
                extracted_file_dict = ref.read([filename])
                extracted_file = extracted_file_dict[filename]
                if filename.endswith(".txt"):
                    with TextIOWrapper(extracted_file, encoding='utf-8', errors='ignore') as text_file:
                        file_txt = text_file.read()
                else:
                    bytesio = extracted_file
                    ...#print(type(bytesio))

            elif archiveType == 'zip':
                extracted_file = ref.read(filename, pwd)
                if filename.endswith(".txt"): file_txt = extracted_file.decode(encoding='utf-8', errors="ignore")
                else: bytesio = BytesIO(extracted_file)

            else:
                return None

            if self.terminateFlag.value == 1:
                try:
                    del extracted_file
                    del file_txt
                    del bytesio
                except:
                    pass
                raise Exception("EXIT")


            if filename.endswith(".txt"):
                notCookieLine = 0
                localSteamCookies = ""
                cookiesFlag = False

                for line in file_txt.split('\n'):
                    line = line.replace('\r', '').strip()
                    if len(line.split("\t")) == 7:
                        if not cookiesFlag:
                            cookiesFlag = True
                        if "steamLoginSecure" in line or "steamRefresh_steam" in line:
                            localSteamCookies += f"{line}\n"
                    elif not cookiesFlag:
                        notCookieLine += 1
                    if notCookieLine > 100:
                        break

                if localSteamCookies:
                    self.progressQueue.put(-2)
                    archiveSteamContent.append(localSteamCookies)

            elif filename.endswith(".zip") and self.check_archives:
                archiveSteamContent += self.readZip(bytesio)

            # elif filename.endswith(".rar") and self.check_archives:
            #     archiveSteamContent += self.readRar(bytesio)

            elif filename.endswith(".7z") and self.check_archives:
                archiveSteamContent += self.read7zip(bytesio)

            else:
                try:
                    del extracted_file
                    del file_txt
                    del bytesio
                except: pass
                return None

        except Exception as e:
            if "EXIT" in str(e): ...
            else:
                ...#(f"CONCUR_READER : {e} | {filename} | {fastTrace(e)}")
            try:
                del extracted_file
                del file_txt
                del bytesio
            except:
                pass
            return None
        else:
            try:
                del extracted_file
                del file_txt
                del bytesio
            except:
                pass
            return archiveSteamContent

class CookiesManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = searcher_new_gui.Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("CookiesParser")

        self.PwdManager = PasswordsManager()

        self.moveUI()
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.initOthers()
        self.initBtns()

        self.steamCookies = []
        self.pwdErrs = []
        self.Processes = []
        self.Walk = None
        self.pathsQueue = None
        self.breaker = False
        self.timer = QTimer(self)
        self.timerWalk = QTimer(self)

    def moveUI(self):
        self.old_position = self.pos()
        self.mouse_pressed = False
        self.softtitle_move_frame.mousePressEvent = self.move_frameMousePressEvent
        self.softtitle_move_frame.mouseMoveEvent = self.move_frameMouseMoveEvent

    def move_frameMousePressEvent(self, event):
        self.offset = event.pos()

    def move_frameMouseMoveEvent(self, event):
        x = event.globalX()
        y = event.globalY()
        x_w = self.offset.x()
        y_w = self.offset.y()
        self.move(x - x_w, y - y_w)

    def initOthers(self):
        self.change_steamCookies.setText("0")
        self.progressBar.setStyleSheet("QProgressBar {border-radius: 10px; border-top-left-radius: 0px; border-top-right-radius: 0px; color: transparent;}"
                                            "QProgressBar::chunk {background-color: black; color: transparent; width: 10px; margin: 0.5px; }")

    def initBtns(self):
        byte_array = QByteArray(IMAGE_B64)
        pixmap = QPixmap()
        pixmap.loadFromData(byte_array)
        self.btn_exit.setIcon(QIcon(pixmap))
        self.btn_exit.clicked.connect(self.myClose)
        self.btn_choose.clicked.connect(self.open_file_dialog)
        self.btn_search.clicked.connect(self.getCookies)
        self.btn_managePasswords.clicked.connect(self.PwdManager.myShow)

    def myClose(self):
        for proc in self.Processes:
            if not proc.terminateFlag.value: proc.terminateFlag.value = 1
        for proc in self.Processes:
            try:
                while proc.terminateFlag.value != 2:
                    sleep(0.5)
                proc.kill()
                self.Processes.remove(proc)
                del proc
            except Exception as e:
                ...#print(f"ERRRRR {e}")
        self.close()

    def open_file_dialog(self):
        options = QFileDialog.Options()
        downloads_directory = str(Path.home() / "Downloads")
        file_name = QFileDialog.getExistingDirectory(self, 'CHOOSE FILE', downloads_directory, options=options)
        self.lineEdit.setText(file_name)

    def getCookies(self):
        def walkProcessTarget(path, queue):
            paths = list(join(root, file) for root, _, files in walk(path) for file in files)
            queue.put(paths)

        self.steamCookies = []
        self.pwdErrs = []
        tempbreaker = False
        for proc in self.Processes:
            if not tempbreaker:
                tempbreaker = True
                self.breaker = True
            if not proc.terminateFlag.value: proc.terminateFlag.value = 1
            while proc.terminateFlag.value != 2:
                sleep(1)
                #print("sleeps")
            res = proc.kill()
        self.Processes.clear()

        if self.Walk is multiprocessing.Process:
            #print("kill")
            self.Walk.kill()
            self.Walk = None
        self.timer.stop()
        self.timerWalk.stop()
        self.pathsQueue = multiprocessing.Queue()
        self.change_steamCookies.setText("0")
        self.change_totalaccs.setText('0')
        self.progressBar.setStyleSheet(
            "QProgressBar {border-radius: 10px; border-top-left-radius: 0px; border-top-right-radius: 0px; color: transparent;}"
            "QProgressBar::chunk {background-color: black; color: transparent; width: 10px; margin: 0.5px; }")

        if not exists(self.lineEdit.text()):
            print("path not exist")
            return

        self.Walk = multiprocessing.Process(daemon=True, target=walkProcessTarget, args=(self.lineEdit.text(), self.pathsQueue,))
        self.Walk.run()

        self.timerWalk.timeout.connect(self.walkHandle)
        self.timerWalk.start(500)

    def walkHandle(self):
        if self.Walk:
            if self.Walk.is_alive(): return

        try:
            paths = self.pathsQueue.get(timeout=1)
        except:
            return


        files_count = len(paths)

        self.progressBar.setValue(0)
        self.progressBar.setMaximum(files_count)
        cpu_count = multiprocessing.cpu_count() - 1
        if cpu_count == 0:
            return

        parts_paths = split_list(paths, cpu_count)
        self.Processes = [ProcessParser(part, self.checkBox_archives.isChecked(), self.PwdManager.pwds) for part in
                          parts_paths]

        for proc in self.Processes:
            proc.start()
        print(f"started {len(self.Processes)} processes")
        self.timerWalk.stop()
        self.timerWalk = QTimer(self)
        self.timer.timeout.connect(self.resultHandle)
        self.timer.start(500)

    def resultHandle(self):

        for proc in self.Processes:
            if self.breaker:
                self.breaker = False
                return

            while not proc.progressQueue.empty():
                if self.breaker:
                    self.breaker = False
                    return
                flag = proc.progressQueue.get()
                if flag == -1:
                    self.progressBar.setValue(self.progressBar.value() + 1)
                elif flag == -2:
                    current_value = int(self.change_steamCookies.text())
                    self.change_steamCookies.setText(f"{current_value + 1}")
                else:
                    self.progressBar.setMaximum(self.progressBar.maximum() + flag)

            if proc.complete.value:
                if self.breaker:
                    self.breaker = False
                    return
                while not proc.progressQueue.empty():
                    if self.breaker:
                        self.breaker = False
                        return
                    flag = proc.progressQueue.get()
                    if flag == -1:
                        self.progressBar.setValue(self.progressBar.value() + 1)
                    elif flag == -2:
                        current_value = int(self.change_steamCookies.text())
                        self.change_steamCookies.setText(f"{current_value + 1}")
                    else:
                        self.progressBar.setMaximum(self.progressBar.maximum() + flag)
                if self.breaker:
                    self.breaker = False
                    return
                proc_res = proc.result.get()
                self.steamCookies += proc_res['cookies']
                self.pwdErrs += proc_res['pwderr']
                proc.kill()
                self.Processes.remove(proc)

        if not len(self.Processes):
            if self.breaker:
                self.breaker = False
                return
            self.saveResults()

    def saveResults(self):

        jwts_ap = set({})
        cookies_formatted = {}

        for i in self.steamCookies:
            try:
                cookies = []
                for line in i.strip().split("\n"):
                    if not line: continue
                    try:
                        domain, flag, path, secure, expiration, name, value = line.split('\t')
                    except:
                        ...#print([line])
                    steamID = value.split("%")[0]

                    if value not in jwts_ap:
                        jwts_ap.add(value)
                        cookies.append({"domain": domain, 'name': name, "value": value})
            except Exception as e:
                ...#print(e)
            else:
                if steamID not in cookies_formatted: cookies_formatted[steamID] = []
                if cookies:
                    cookies_formatted[steamID] += cookies

        cleared_cookies = []

        for steamId, cookies in cookies_formatted.items():
            refresh = None
            community = None
            store_powered = None
            help_powered = None

            for cookie in cookies:
                if cookie['name'] == "steamRefresh_steam":
                    refresh = cookie
                if cookie['name'] == "steamLoginSecure" and cookie['domain'] == "store.steampowered.com":
                    store_powered = cookie
                if cookie['name'] == "steamLoginSecure" and cookie['domain'] == "help.steampowered.com":
                    help_powered = cookie
                if cookie['name'] == "steamLoginSecure" and cookie['domain'] == "steamcommunity.com":
                    community = cookie

            if refresh:
                cleared_cookies.append([refresh])
            elif community and not (help_powered and store_powered):
                cleared_cookies.append([community])
            elif community and (help_powered and store_powered):
                cleared_cookies.append([community, store_powered, help_powered])
            else:
                ...


        self.change_totalaccs.setText(f"{len(cleared_cookies)}")

        folderr = save_results(cleared_cookies)
        if self.pwdErrs:
            with open(join(folderr, "pwdNotFoundInfo.txt"), 'w', encoding='utf-8', errors="ignore") as f:
                for i in self.pwdErrs:
                    if i:
                        f.write(f"{i}\n\n")
        try:
            full_path = join(getcwd(), folderr)
            startfile(abspath(full_path))
        except Exception as e:
            print(f"ERROR OPEN PATH {fastTrace(e)}")
            ...#print(fastTrace(e))
        ...#print(f"complete {len(self.steamCookies)} steam cookies")
        self.progressBar.setStyleSheet(
            "QProgressBar {border-radius: 10px; border-top-left-radius: 0px; border-top-right-radius: 0px; color: transparent;}"
            "QProgressBar::chunk {background-color: grey; color: transparent; width: 10px; margin: 0.5px; }")
        self.timer.stop()
        self.timer = QTimer(self)

class PasswordsManager(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = passwords_manager.Ui_Form()
        self.ui.setupUi(self)
        self.setWindowTitle("PasswordManager")
        self.moveUI()
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self.listWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listWidget.customContextMenuRequested.connect(self.show_context_menu)

        self.initPasswords()
        self.initOthers()
        self.initBtns()

    def show_context_menu(self, pos: QPoint):
        item = self.listWidget.itemAt(pos)
        if item:
            menu = QMenu(self.listWidget)

            delete_action = QAction("Remove", self)
            delete_action.triggered.connect(lambda: self.delete_item(item))
            menu.addAction(delete_action)
            menu.setStyleSheet("""
                        QMenu {
                            background-color: white;
                            border: 1px solid grey;
                            border-radius: none;
                            font-family: 'Malgun Gothic';
                            font-size: 8pt;
                        }
                        QMenu::item {
                            color: grey;
                            background-color: transparent;
                        }
                        QMenu::item:selected {
                            background-color: rgb(242, 242, 242);
                            color: grey;
                        }
                    """)

            menu.exec_(self.listWidget.mapToGlobal(pos))

    def delete_item(self, item):
        pwd = item.text()
        self.pwds.remove(pwd)
        self.saveJson()
        self.listWidget.takeItem(self.listWidget.row(item))

    def initPasswords(self):
        if not exists("pwds.json"):
            with open("pwds.json", 'w', encoding='utf-8', errors='ignore') as f:
                dump([], f)
                self.pwds = []
        else:
            try:
                with open("pwds.json", encoding='utf-8', errors='ignore') as f:
                    pwds = load(f)
                    if type(pwds) == type([1, 2]):
                        self.pwds = pwds
                    else:
                        self.pwds = []

            except Exception as e:
                ...#print(f"READ JSON ERROR {e}")
                self.pwds = []

    def saveJson(self):
        try:
            with open("pwds.json", 'w', encoding='utf-8', errors='ignore') as f:
                dump(self.pwds, f)
        except Exception as e:
            ...#print(f"DUMP JSON ERROR {e}")

    def myShow(self):
        self.show()

    def moveUI(self):
        self.old_position = self.pos()
        self.mouse_pressed = False
        self.softtitle_move_frame.mousePressEvent = self.move_frameMousePressEvent
        self.softtitle_move_frame.mouseMoveEvent = self.move_frameMouseMoveEvent

    def move_frameMousePressEvent(self, event):
        self.offset = event.pos()

    def move_frameMouseMoveEvent(self, event):
        x = event.globalX()
        y = event.globalY()
        x_w = self.offset.x()
        y_w = self.offset.y()
        self.move(x - x_w, y - y_w)

    def initOthers(self):
        existing_items = [self.listWidget.item(i).text() for i in range(self.listWidget.count())]

        for pwd in self.pwds:
            if pwd not in existing_items:
                self.listWidget.addItem(pwd)

    def initBtns(self):
        byte_array = QByteArray(IMAGE_B64)
        pixmap = QPixmap()
        pixmap.loadFromData(byte_array)
        self.btn_exit.setIcon(QIcon(pixmap))
        self.btn_exit.clicked.connect(self.close)
        self.btn_add.clicked.connect(self.addPassword)

        self.btn_exit.setAutoDefault(False)
        self.btn_add.setAutoDefault(False)

    def addPassword(self):
        password = self.lineEdit.text()

        if password and password not in self.pwds:
            self.pwds.append(password)
            self.saveJson()

        self.initOthers()
        self.lineEdit.setText(f"")

def save_results(cookies):
    def MERGE(refreshes=None, help_powered=None, store_powered=None, community=None):
        _file = ""
        if refreshes:
            _file += f"""{WRITER_REFRESH_TOKENS}\n"""
            for i in refreshes: _file += f"{i}\n"

        if community:
            _file += f"""{WRITER_COMMUNITY}\n"""
            for i in community: _file += f"{i}\n"

        if help_powered:
            _file += f"""{WRITER_HELP_STEAM_POWERED}\n"""
            for i in help_powered: _file += f"{i}\n"

        if store_powered:
            _file += f"""{WRITER_STORE_STEAM_POWERED}\n"""
            for i in store_powered: _file += f"{i}\n"
        return _file
    def OPTIMIZATED_CHECKSIZE(refreshes=None, help_powered=None, store_powered=None, community=None):
        size = 0
        if refreshes:
            size += len(f"""{WRITER_REFRESH_TOKENS}\n""")
            size += len(refreshes) * 500

        if community:
            size += len("""{WRITER_COMMUNITY}\n""")
            size += len(community) * 500

        if help_powered:
            size += len("""{WRITER_HELP_STEAM_POWERED}\n""")
            size += len(help_powered) * 500

        if store_powered:
            size += len("""{WRITER_STORE_STEAM_POWERED}\n""")
            size += len(store_powered) * 500
        return size

    refreshes = []
    help_powered = []
    store_powered = []
    community = []
    files = []
    lastSavedIndex = 0
    cookies_size = len(cookies)

    for inde, cookie in enumerate(cookies):
        for obj in cookie:
            if obj['domain'] == "login.steampowered.com":
                refreshes.append(obj['value'])
            if obj['domain'] == "steamcommunity.com":
                community.append(obj['value'])
            if obj['domain'] == "help.steampowered.com":
                help_powered.append(obj['value'])
            if obj['domain'] == "store.steampowered.com":
                store_powered.append(obj['value'])

        if OPTIMIZATED_CHECKSIZE(refreshes, help_powered, store_powered, community) > MAX_FILE_SIZE:
            files.append(MERGE(refreshes, help_powered, store_powered, community))
            refreshes = []
            help_powered = []
            store_powered = []
            community = []

    if CHECK_SIZE(MERGE(refreshes, help_powered, store_powered, community)) < MAX_FILE_SIZE:
        files.append(MERGE(refreshes, help_powered, store_powered, community))

    folderr = f'results [{strftime("%m-%d %H-%M-%S", gmtime())}]'
    folder = mkdir(folderr)
    for indexx, file in enumerate(files):
        with open(join(folderr, f"output_{indexx}.qs"), 'w', encoding='utf-8', errors='ignore') as f:
            f.write(file)
    #print('end writing')
    return folderr


def split_list(lst, n):
    k, m = divmod(len(lst), n)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]
def fastTrace(exc):
    ln = ""
    traceback_obj = exc.__traceback__
    while traceback_obj is not None:
        frame = traceback_obj.tb_frame
        line = traceback_obj.tb_lineno
        filename = frame.f_code.co_filename
        ln += f" {line} ({filename.split('\\')[-1]});"
        traceback_obj = traceback_obj.tb_next
    err = str(exc)
    err_type = str(type(exc))
    return ln[:-1], err, err_type

if __name__ == "__main__":
    multiprocessing.freeze_support()
    import atexit
    import signal
    from sys import exit as _ext
    from sys import argv
    def cleanup():
        try:
            for proc in window.Processes:

                try:
                    if not proc.terminateFlag.value: proc.terminateFlag.value = 1
                except:
                    ...#print("false terminate")

            for proc in window.Processes:
                try:
                    while proc.terminateFlag.value != 2:
                        sleep(0.5)

                    proc.kill()
                    del proc
                except Exception as e:
                    ...#print(f"false closing {e}")

        except:
            pass


    def signal_handler(signum, frame):
        cleanup()
        _ext(0)


    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    app = QApplication(argv)

    window = CookiesManager()
    window.show()

    app.exec_()
