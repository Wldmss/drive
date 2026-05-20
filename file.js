import { Alert, Platform } from 'react-native';
import * as FileSystem from 'expo-file-system';
import RNFetchBlob from 'rn-fetch-blob';
import * as RNFS from 'react-native-fs';
import { dispatchOne } from './DispatchUtils';
import { startActivityAsync } from 'expo-intent-launcher';
import { isAvailableAsync, shareAsync } from 'expo-sharing';
import PropTypes from 'prop-types';

export const fileStore = (_store) => {
    store = _store;
};

/** 파일 util */

// 파일 다운로드 (fetch)
export const downloadAttachment = async (url, fileData) => {
    let fileName = fileData.fileNm || null;
    const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

    try {
        store.dispatch(dispatchOne('SET_SNACK', { message: '다운로드를 시작합니다.', hold: true }));

        // 파일 다운로드
        const response = await fetch(url, {
            headers: {
                'User-Agent': userAgent,
            },
        });

        if (!response.ok) {
            failDownload();
            return;
        } else {
            store.dispatch(dispatchOne('SET_SNACK', { message: `다운로드 중...`, hold: true }));

            if (!fileName) {
                const contentDisposition = response.headers.get('Content-Disposition') || response.headers.get('content-disposition');

                if (contentDisposition && contentDisposition.includes('attachment')) {
                    const filenameMatch = contentDisposition.match(/filename\*=([^;]+)|filename="([^"]+)"/);

                    if (filenameMatch) {
                        if (filenameMatch[1]) {
                            // Decode RFC 5987 encoded filename
                            const encodedFilename = filenameMatch[1].split("''")[1];
                            fileName = decodeURIComponent(encodedFilename);
                        } else if (filenameMatch[2]) {
                            // Handle regular filename with double quotes
                            fileName = filenameMatch[2];
                        }
                    }
                }

                if (!fileName) {
                    // Fallback to using the URL to infer the filename
                    fileName = url.split('/').pop().split('?')[0];
                }

                if (fileName == null) {
                    // const extension = fileName.split('.').pop();
                    Alert.alert('올바르지 않은 경로입니다.\n다시 시도해주세요.');
                    return;
                }
            }
        }

        const blob = await response.blob();

        // 파일 다운로드 사이즈 제한 해제
        // const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

        // // 파일 사이즈 큰 경우 예외 처리
        // if (blob.size > MAX_FILE_SIZE) {
        //     store.dispatch(dispatchOne('SET_SNACK', { message: '파일이 너무 커서 다운로드할 수 없습니다.', hold: false }));
        //     return;
        // }

        const dir = FileSystem.documentDirectory;
        let downloadPath = `${dir}/${fileName}`;

        if (Platform.OS == 'android') {
            // 앱 내 저장소에 저장됨
            const fileExists = await FileSystem.getInfoAsync(downloadPath);
            if (fileExists.exists) {
                await FileSystem.deleteAsync(downloadPath);
            }
        } else {
            // ios 파일이 덮어진다
            const uniqueFileName = await getUniqueFileName(dir, fileName);
            downloadPath = `${dir}/${uniqueFileName}`;
        }

        const reader = new FileReader();

        reader.onloadend = async () => {
            const base64data = reader.result.split(',')[1];
            await FileSystem.writeAsStringAsync(downloadPath, base64data, {
                encoding: FileSystem.EncodingType.Base64,
            });

            if (Platform.OS == 'android') {
                downloadAndroid(downloadPath, fileName);
            } else {
                const contentType = response.headers.get('Content-Type') || response.headers.get('content-type') || blob.type;
                const mimeType = contentType != null ? contentType.split(';')[0] : null;

                openIos(downloadPath, mimeType);
            }
        };

        reader.onprogress = (event) => {
            if (event.lengthComputable) {
                const percent = Math.round((event.loaded / event.total) * 100);
                store.dispatch(dispatchOne('SET_SNACK', { message: `다운로드 중... (${percent}%)`, hold: true }));
            } else {
                store.dispatch(dispatchOne('SET_SNACK', { message: `다운로드 중...`, hold: true }));
            }
        };

        reader.onerror = function () {
            failDownload();
        };

        reader.readAsDataURL(blob);
    } catch (error) {
        failDownload();
    }
};

downloadAttachment.propTypes = {
    url: PropTypes.string.isRequired,
    fileData: PropTypes.shape({
        fileNm: PropTypes.string,
    }),
};

// android 파일 저장 : 단말 저장은 따로 해줘야 함
const downloadAndroid = async (uri, fileName) => {
    try {
        const result = await FileSystem.getInfoAsync(uri);

        if (result.exists) {
            const dir = RNFS.DownloadDirectoryPath; // android 저장경로
            const uniqueFileName = await getUniqueFileName(dir, fileName);
            const filePath = `${dir}/${uniqueFileName}`;

            try {
                // 단말에 파일 저장
                const fileExists = await RNFS.exists(filePath);

                if (fileExists) {
                    await RNFS.unlink(filePath);
                }

                const tempFilePath = `${filePath}.tmp`;

                await RNFS.copyFile(uri, tempFilePath);

                await RNFS.moveFile(tempFilePath, filePath);
            } catch (error) {
                console.error(error);
            }

            finishDownload();
            openAndroid(uri);
        } else {
            failDownload();
        }
    } catch (error) {
        failDownload();
        console.error(error);
    }
};

// android 파일 열기
export const openAndroid = (uri) => {
    const isZipFile = uri.match(/\.zip$/i);

    new Promise((resolve) => setTimeout(resolve, 500)).then(async () => {
        await FileSystem.getContentUriAsync(uri).then(async (cUri) => {
            let launcherParams = {
                data: cUri,
                flags: 1,
            };

            if (isZipFile) {
                launcherParams['type'] = 'application/zip';
            }

            await startActivityAsync('android.intent.action.VIEW', launcherParams);
        });
    });
};

// ios 파일 열기 : ios 는 expo-file-system 만으로도 단말에 저장됨
const openIos = async (uri, mimeType) => {
    finishDownload();

    try {
        // 파일 열기
        RNFetchBlob.ios.openDocument(uri);
    } catch (err) {
        // 파일 share
        if (mimeType && (await isAvailableAsync())) {
            await shareAsync(uri, {
                UTI: mimeType,
                mimeType: mimeType,
            });
        }
    }
};

// 다운로드 완료
const finishDownload = () => {
    store.dispatch(dispatchOne('SET_SNACK', { message: `다운로드가 완료되었습니다.`, hold: false, time: 2000 })); // \n${filePath}
};

// 다운로드 실패
const failDownload = () => {
    store.dispatch(dispatchOne('SET_SNACK', { message: '다운로드에 실패하였습니다.', hold: false }));
};

// ios, android 다운로드 분기 처리 (사용 x)
export const downloadFileMulti = (url, fileName) => {
    if (Platform.OS == 'ios') {
        downloadBlobFile(url, fileName);
    } else {
        downloadFs(url, fileName);
    }
};

// rn-fetch-blob :: android 14 이상 RECEIVER_EXPORTED or RECEIVER_NOT_EXPORTED 설정 해줘야 함 (사용 x)
export const downloadBlobFile = (url, fileData) => {
    let fileName = fileData.fileNm || null;

    if (!fileName) {
        const fileArr = url.split('/');
        fileName = fileArr[fileArr.length - 1];
    }

    let DownloadDir = RNFetchBlob.fs.dirs.DownloadDir; // android 저장경로
    let DocumentDir = RNFetchBlob.fs.dirs.DocumentDir; // ios 저장경로

    const dir = Platform.OS == 'android' ? DownloadDir : DocumentDir;

    const commonconfig = {
        useDownloadManager: true,
        notification: true,
        mediaScannable: true,
        title: fileName,
    };

    const configfb = {
        fileCache: true,
        addAndroidDownloads: {
            ...commonconfig,
            path: `${dir}/${fileName}`,
        },
        ...commonconfig,
        path: `${dir}/${fileName}`,
    };

    store.dispatch(dispatchOne('SET_SNACK', { message: '다운로드를 시작합니다.', hold: true }));
    RNFetchBlob.config(configfb)
        .fetch('POST', url, fileData)
        .progress((res) => {
            store.dispatch(dispatchOne('SET_SNACK', { message: `다운로드 중...`, hold: true }));
        })
        .then((res) => {
            if (Platform.OS === 'ios') {
                RNFetchBlob.fs.writeFile(configfb.path, res.data, 'base64');
                RNFetchBlob.ios.previewDocument(configfb.path);
            }

            if (Platform.OS === 'android') {
            }

            store.dispatch(dispatchOne('SET_SNACK', { message: `다운로드가 완료되었습니다.`, hold: false, time: 5000 }));
        });
};
