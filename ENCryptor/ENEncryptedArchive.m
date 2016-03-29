//
//  ENEncryptedArchive.m
//  Encrypto
//
//  Created by Nickolay O. on 11/27/14.
//  Copyright (c) 2014 MacPaw. All rights reserved.
//

#import "ENEncryptedArchive.h"
#import "ENFileMetadata.h"
#import <CommonCrypto/CommonCrypto.h>
#import "sys/stat.h"
#import "zlib.h"

@interface ENEncryptedArchiveDirectoryLocator : NSObject

@property UInt64 directoryPosition;
@property UInt64 directorySize;
@property UInt64 reserved1;
@property UInt64 reserved2;
@property UInt32 version;
@property UInt32 flags;
@property (strong) NSString *passwordHint;
@property (strong) NSData *salt;
@property (strong) NSData *hmac;
@property (strong) NSData *preview;

- (NSMutableData *)save;

- (BOOL)load:(NSData *)aData;

@end

/* Keys and values for delegate info dictionaries */
NSString *const kEncryptedArchiveOperation = @"operation";
NSString *const kEncryptedArchiveItem = @"item";
NSString *const kEncryptedArchiveError = @"error";
NSString *const kEncryptedArchiveUnderlyingError = @"underlying_error";
NSString *const kEncryptedArchiveItemProgress = @"progress";
NSString *const kEncryptedArchiveTotalProgress = @"total_progress";

NSString *const kEncryptedArchiveOperationAddition = @"EncryptedArchiveOperationAddition";
NSString *const kEncryptedArchiveOperationSaving = @"EncryptedArchiveOperationSaving";
NSString *const kEncryptedArchiveOperationExtraction = @"EncryptedArchiveOperationExtraction";
NSString *const kEncryptedArchiveOperationOpening = @"EncryptedArchiveOperationOpening";

/* Error messages and codes */
NSString *const ENEncryptedArchiveErrorDomain = @"ENEncryptedArchiveErrorDomain";
const int ENEncryptedArchiveErrorOperationCancelled = 1000;
const int ENEncryptedArchiveFileCreationFailed = 1001;
const int ENEncryptedArchiveFileOpeningFailed = 1002;
const int ENEncryptedArchiveFileReadingFailed = 1003;
const int ENEncryptedArchiveLocalHeaderCreationFailed = 1004;
const int ENEncryptedArchiveDirectoryHeaderCreationFailed = 1005;
const int ENEncryptedArchiveDirectoryEncryptionFailed = 1006;
const int ENEncryptedArchiveEncryptionFailed = 1007;
const int ENEncryptedArchiveCompressionFailed = 1008;
const int ENEncryptedArchiveErrorDirectoryHMACMismatch = 1009;
const int ENEncryptedArchiveOpeningFailed = 1101;
const int ENEncryptedArchiveMagicCheckFailed = 1102;
const int ENEncryptedArchiveInvalidDirectoryLocatorSize = 1103;
const int ENEncryptedArchiveInvalidDirectoryLocator = 1104;
const int ENEncryptedArchiveUnsupportedVersion = 1105;
const int ENEncryptedArchiveInvalidDirectoryRecord = 1106;
const int ENEncryptedArchiveInvalidEncryptionSettings = 1107;
const int ENEncryptedArchiveArchiveNotOpened = 1201;
const int ENEncryptedArchiveNoOutputDirectory = 1202;
const int ENEncryptedArchiveUnknownItemType = 1203;
const int ENEncryptedArchiveCannotCreateExtractionFile = 1204;
const int ENEncryptedArchiveCannotReadLocalHeader = 1205;
const int ENEncryptedArchiveInvalidLocalHeader = 1206;
const int ENEncryptedArchiveItemExtractionFailed = 1207;
const int ENEncryptedArchiveDecryptionFailed = 1208;
const int ENEncryptedArchiveNoPasswordSpecified = 1209;
const int ENEncryptedArchiveInvalidPassword = 1210;
const int ENEncryptedArchiveDecompressionFailed = 1211;
const int ENEncryptedArchiveHMACCheckFailed = 1212;

/* Header field identifiers, magic numbers, etc. In reversed order because of little endian CPU */
const UInt32 ENEncryptoHeader = '1EPM';
//'MPE1';
const UInt32 ENHeaderLocalFile = 'CLDH';
//'HDLC';
const UInt32 ENHeaderDirectory = 'RDDH';
//'HDDR';
const UInt32 ENHeaderLocator = 'TCLH';
//'HLCT';
const UInt32 ENHeaderElementFileType = 'PYTF';
//'FTYP';
const UInt32 ENHeaderElementFileSize = 'ZISF';
//'FSIZ';
const UInt32 ENHeaderElementFilePath = 'TAPF';
//'FPAT';
const UInt32 ENHeaderElementFilePerm = 'MRPF';
//'FPRM';
const UInt32 ENHeaderElementFileOwner = 'NWOF';
//'FOWN';
const UInt32 ENHeaderElementFileGroup = 'PRGF';
//'FGRP';
const UInt32 ENHeaderElementFileMDat = 'TDMF';
//'FMDT';
const UInt32 ENHeaderElementFileCDat = 'TCMF';
//'FCDT';
const UInt32 ENHeaderElementFileUTI = 'ITUF';
//'FUTI';
const UInt32 ENHeaderElementFileHMAC = 'CMHF';
//'FHMC';
const UInt32 ENHeaderElementFileFlags = 'GLFF';
//'FFLG';
const UInt32 ENHeaderElementFileCSize = 'ZSCF';
//'FCSZ';
const UInt32 ENHeaderElementLinkDestination = 'KNLF';
//'FLNK';
const UInt32 ENHeaderElementExAttrs = 'AXEF';
//'FEXA';
const UInt32 ENHeaderElementExSecOptions = 'SXEF';
//'FEXS';
const UInt32 ENHeaderElementFileLocator = 'TCLF';
//'FLCT';
const UInt32 ENHeaderElementPadding = 'NDPF';
//'FPDN';
const UInt32 ENHeaderElementDirLocator = 'TCLD';
//'DLCT';
//const UInt32 ENHeaderElementDirSize = 'ZISD';
// 'DSIZ';
const UInt32 ENHeaderElementDirFlags = 'GLFD';
//'DFLG';
const UInt32 ENHeaderElementMasterSalt = 'TLSM';
//'MSLT';
const UInt32 ENHeaderElementDirLocatorSize = 'ZSLD';
//'DLSZ';
const UInt32 ENHeaderElementDirLocatorVer = 'RVLD';
//'DLVR';
const UInt32 ENHeaderElementPasswordHint = 'NHSP';
//'PSHN';
const UInt32 ENHeaderElementArchivePreview = 'VWRP';
//'PRWV'
const UInt32 ENHeaderElementDirHMAC = 'CMHD';
//'DHMC'
// reserved encrypted field for DirLocator. Used to check password.
const UInt64 ENHeaderElementaDirLocatorR1 = 0x3145565245534552;// 'RESERVE1'

const UInt8 ENHeaderFileTypeRegular = 0x00;
const UInt8 ENHeaderFileTypeDirectory = 0x01;
const UInt8 ENHeaderFileTypeSymLink = 0x02;

const UInt32 ENFlagEncryptFiles = 0x01;
const UInt32 ENFlagEncryptDirectory = 0x02;
const UInt32 ENFlagHmacFiles = 0x04;
const UInt32 ENFlagHmacDirectory = 0x08;
const UInt32 ENFlagCompressFiles = 0x10;

const UInt32 ENFlagAES128 = 0x01;
const UInt32 ENFlagAES192 = 0x02;
const UInt32 ENFlagAES256 = 0x03;

const UInt32 ENCR_BLOCK_SIZE = 16;
const UInt32 ENCR_BASE_KEY_SIZE = 16;
const UInt32 ENCR_PBKDF2_ROUNDS = 4096;
const UInt32 ENCR_SALT_LENGTH = 16;
const UInt32 ENCR_HMAC_KEY_LEN = 16;
const UInt32 ENCR_HMAC_LEN = CC_SHA256_DIGEST_LENGTH;
const UInt32 OUTPUT_BLOCK_SIZE = 16 * 1024; // size of blocks to read from/write to files.

@interface ENEncryptedArchive () {
    NSMutableDictionary *_directory;
    NSMutableDictionary *_directoryTree;
    int _archiveFileFd;
    NSString *_archiveFilePath;
    UInt64 _archiveSize;
    UInt64 _directorySize;
    int _inputFd;
    BOOL _archiveOpened;
    UInt64 _operationTotal;
    UInt64 _operationProcessed;
    BOOL _extractionCancelled;
    NSData *_masterKey;
    NSData *_masterSalt;
    CCCryptorRef _outputCrypto;
    NSMutableData *_outputCryptoCache;
    CCCryptorRef _inputCrypto;
    NSMutableData *_inputCryptoCache;
    NSMutableData *_inputDecryptedCache;
    z_streamp _compressionStream;
    z_streamp _decompressionStream;
    CCHmacContext _hmac;
    BOOL _calculatingHmac;
    NSData *_lastHmac;
}
@end

@interface ENEncryptedArchiveItem ()

+ (ENEncryptedArchiveItem *)itemFromPath:(NSString *)aPath error:(NSError **)anError;

@end

@implementation ENEncryptedArchive

- (instancetype)init {
    self = [super init];
    if (self) {
        _directory = [[NSMutableDictionary alloc] init];
        _directoryTree = [[NSMutableDictionary alloc] init];
        _archiveOpened = NO;
        _inputFd = -1;
        _archiveFileFd = -1;

        self.delegate = nil;
        self.encryptFiles = YES;
        self.encryptDirectory = YES;
        self.calculateDirectoryHmac = YES;
        self.calculateFilesHmac = YES;
        self.AESKeyBits = 128;
        self.password = @"";
        self.passwordHint = @"";
        self.compressFiles = YES;
        self.compressionLevel = 6;
        _masterKey = nil;
        _masterSalt = nil;
        _outputCrypto = NULL;
        _inputCrypto = NULL;
        _compressionStream = NULL;
        _decompressionStream = NULL;
        _calculatingHmac = NO;
    }

    return self;
}

+ (ENEncryptedArchive *)archive {
    return [[ENEncryptedArchive alloc] init];
}

- (NSArray *)fileRecords {
    return [_directory allValues];
}

- (void)addToDirectory:(ENEncryptedArchiveItem *)anItem {
    _directory[anItem.path.lowercaseString] = anItem;
    NSString *parent = [anItem.path.lowercaseString stringByDeletingLastPathComponent];
    if (!parent || (parent.length == 0))
        parent = @"/";

    NSMutableArray *items = _directoryTree[parent];
    if (!items) {
        items = [NSMutableArray new];
        _directoryTree[parent] = items;
    }
    [items addObject:anItem];

    if (!self.includeApplications && [[anItem.path pathExtension] isEqualTo:@"app"]) {
        _includeApplications = YES;
    }
}

- (NSArray *)childRecordsAtPath:(NSString *)aPath {
    if (!aPath || (aPath.length == 0))
        aPath = @"/";

    NSArray *items = _directoryTree[[aPath lowercaseString]];
    if (!items)
        items = [NSArray array];

    return items;
}

- (NSArray *)childRecords:(ENEncryptedArchiveItem *)anItem {
    if (!anItem)
        return [self childRecordsAtPath:@"/"];
    else
        return [self childRecordsAtPath:anItem.path];
}

- (ENEncryptedArchiveItem *)recordAtPath:(NSString *)aPath {
    return _directory[[aPath lowercaseString]];
}

- (void)reportOpenError:(int)errorCode lowError:(NSError *)lowError {
    if ((self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationError:)])) {
        NSError *error = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:errorCode userInfo:nil];
        NSMutableDictionary *infoDict = [NSMutableDictionary dictionary];
        if (lowError)
            infoDict[kEncryptedArchiveUnderlyingError] = lowError;
        infoDict[kEncryptedArchiveError] = error;
        infoDict[kEncryptedArchiveOperation] = kEncryptedArchiveOperationOpening;

        _archiveOpened = NO;
        if (_inputFd != -1) {
            close(_inputFd);
            _inputFd = -1;
        }

        [self.delegate encryptedArchive:self operationError:infoDict];
    }
}

- (BOOL)inputData:(void *)data ofSize:(NSUInteger)size {
    void *stData = data;
    NSUInteger stSize = size;

    if (_inputFd != -1) {
        if (!_inputCrypto) {
            size_t rd = read(_inputFd, data, size);
            if (rd != size)
                return NO;
            else {
                if (_calculatingHmac)
                    CCHmacUpdate(&_hmac, data, size);
                return YES;
            }
        }
        else {
            if (_inputDecryptedCache.length >= size) {
                memmove(data, _inputDecryptedCache.mutableBytes, size);
                if (size < _inputDecryptedCache.length)
                    memmove(_inputDecryptedCache.mutableBytes, _inputDecryptedCache.mutableBytes + size, _inputDecryptedCache.length - size);
                [_inputDecryptedCache setLength:_inputDecryptedCache.length - size];

                if (_calculatingHmac)
                    CCHmacUpdate(&_hmac, stData, stSize);

                return YES;
            }
            else if (_inputDecryptedCache.length > 0) {
                memmove(data, _inputDecryptedCache.mutableBytes, _inputDecryptedCache.length);
                data += _inputDecryptedCache.length;
                size -= _inputDecryptedCache.length;
                [_inputDecryptedCache setLength:0];
            }

            size_t toRead = size + (ENCR_BLOCK_SIZE - ((ENCR_BLOCK_SIZE + size - 1) % ENCR_BLOCK_SIZE + 1));

            //while (CCCryptorGetOutputLength(_inputCrypto, toRead, NO) < size)
            //    toRead += ENCR_BLOCK_SIZE;

            if (_inputCryptoCache.length < toRead)
                [_inputCryptoCache setLength:toRead];

            size_t rd = read(_inputFd, _inputCryptoCache.mutableBytes, toRead);
            if (rd != toRead)
                return NO;

            int res = CCCryptorUpdate(_inputCrypto, _inputCryptoCache.mutableBytes, toRead, _inputCryptoCache.mutableBytes, toRead, &rd);
            if (res != kCCSuccess) {
                NSLog(@"Warning! Decryption update failed. Error %d", res);
                return NO;
            }

            memmove(data, _inputCryptoCache.mutableBytes, size);
            if (size < toRead) {
                [_inputDecryptedCache setLength:toRead - size];
                memmove(_inputDecryptedCache.mutableBytes, _inputCryptoCache.mutableBytes + size, toRead - size);
            }

            if (_calculatingHmac)
                CCHmacUpdate(&_hmac, stData, stSize);

            return YES;
        }
    }
    else
        return NO;
}

- (BOOL)loadArchiveItem:(ENEncryptedArchiveItem *)item fromData:(NSData *)aData {
    /* loading ENEncryptedArchiveItem from directory or updating it from local file entry */
    UInt32 hdr;
    NSUInteger idx = 0, size = aData.length;

    while (size > 0) {
        if (size < 4)
            return NO;
        else
            hdr = *((UInt32 *) (aData.bytes + idx));

        idx += 4;
        size -= 4;

        switch (hdr) {
            case ENHeaderElementFileType: {
                if (size < 1)
                    return NO;
                UInt8 fType = *((UInt8 *) (aData.bytes + idx));
                idx++;
                size--;

                if (fType == ENHeaderFileTypeRegular)
                    [item.attributes setObject:NSFileTypeRegular forKey:NSFileType];
                else if (fType == ENHeaderFileTypeDirectory)
                    [item.attributes setObject:NSFileTypeDirectory forKey:NSFileType];
                else if (fType == ENHeaderFileTypeSymLink)
                    [item.attributes setObject:NSFileTypeSymbolicLink forKey:NSFileType];
                else
                    return NO;

                break;
            }
            case ENHeaderElementFileFlags: {
                if (size < 4)
                    return NO;
                UInt32 flg = *((UInt32 *) (aData.bytes + idx));
                item.compressed = (flg & ENFlagCompressFiles) != 0;

                idx += 4;
                size -= 4;

                break;
            }
            case ENHeaderElementFileSize: {
                if (size < 8)
                    return NO;
                item.size = *((UInt64 *) (aData.bytes + idx));
                [item.attributes setObject:[NSNumber numberWithUnsignedLongLong:item.size] forKey:NSFileSize];
                idx += 8;
                size -= 8;

                break;
            }
            case ENHeaderElementFileCSize: {
                if (size < 8)
                    return NO;
                item.compressedSize = *((UInt64 *) (aData.bytes + idx));
                idx += 8;
                size -= 8;

                break;
            }
            case ENHeaderElementFilePath: {
                if (size < 2)
                    return NO;
                UInt16 pSize = *((UInt16 *) (aData.bytes + idx));
                if (size < 2 + pSize)
                    return NO;

                NSString *path = [[NSString alloc] initWithBytes:aData.bytes + idx + 2 length:pSize encoding:NSUTF8StringEncoding];
                if (!path)
                    return NO;
                item.path = path;
                idx += 2 + pSize;
                size -= 2 + pSize;
                break;
            }
            case ENHeaderElementFilePerm: {
                if (size < 2)
                    return NO;
                UInt16 perm = *((UInt16 *) (aData.bytes + idx));
                [item.attributes setObject:[NSNumber numberWithShort:perm] forKey:NSFilePosixPermissions];

                idx += 2;
                size -= 2;

                break;
            }
            case ENHeaderElementFileOwner: {
                if (size < 2)
                    return NO;
//                UInt16 owner = *((UInt16*)(aData.bytes + idx));
//                [item.attributes setObject:[NSNumber numberWithShort:owner] forKey:NSFileOwnerAccountID];

                idx += 2;
                size -= 2;

                break;
            }
            case ENHeaderElementFileGroup: {
                if (size < 2)
                    return NO;
//                UInt16 group = *((UInt16*)(aData.bytes + idx));
//                [item.attributes setObject:[NSNumber numberWithShort:group] forKey:NSFileGroupOwnerAccountID];

                idx += 2;
                size -= 2;

                break;
            }
            case ENHeaderElementFileMDat: {
                if (size < 8)
                    return NO;
                UInt64 mdat = *((UInt64 *) (aData.bytes + idx));
                [item.attributes setObject:[NSDate dateWithTimeIntervalSince1970:(NSTimeInterval) mdat / 1000.0] forKey:NSFileModificationDate];

                idx += 8;
                size -= 8;

                break;
            }
            case ENHeaderElementFileCDat: {
                if (size < 8)
                    return NO;
                UInt64 cdat = *((UInt64 *) (aData.bytes + idx));
                [item.attributes setObject:[NSDate dateWithTimeIntervalSince1970:(NSTimeInterval) cdat / 1000.0] forKey:NSFileCreationDate];

                idx += 8;
                size -= 8;

                break;
            }
            case ENHeaderElementFileUTI: {
                if (size < 2)
                    return NO;
                UInt16 pSize = *((UInt16 *) (aData.bytes + idx));
                if (size < 2 + pSize)
                    return NO;

                NSString *uti = [[NSString alloc] initWithBytes:aData.bytes + idx + 2 length:pSize encoding:NSUTF8StringEncoding];
                if (!uti)
                    return NO;
                item.UTI = uti;

                idx += 2 + pSize;
                size -= 2 + pSize;

                break;
            }
            case ENHeaderElementExAttrs: {
                if (size < 4)
                    return NO;
                UInt32 aSize = *((UInt32 *) (aData.bytes + idx));
                if (size < 4 + aSize)
                    return NO;

                NSData *exAttrData = [NSData dataWithBytes:(void *) (aData.bytes + idx + 4) length:aSize];
                @try {
                    NSDictionary *exAttrs = [NSKeyedUnarchiver unarchiveObjectWithData:exAttrData];
                    [item.extendedAttributes addEntriesFromDictionary:exAttrs];
                }
                @catch (NSException *ex) {
                    return NO;
                }

                idx += 4 + aSize;
                size -= 4 + aSize;

                break;
            }
            case ENHeaderElementExSecOptions: {
                if (size < 4)
                    return NO;
                UInt32 aSize = *((UInt32 *) (aData.bytes + idx));
                if (size < 4 + aSize)
                    return NO;

                NSData *exSecData = [NSData dataWithBytes:(void *) (aData.bytes + idx + 4) length:aSize];
                item.extendedSecurityOptions = exSecData;

                idx += 4 + aSize;
                size -= 4 + aSize;

                break;
            }
            case ENHeaderElementFileLocator: {
                if (size < 8)
                    return NO;
                item.localHeaderPosition = *((UInt64 *) (aData.bytes + idx));

                idx += 8;
                size -= 8;

                break;
            }
            case ENHeaderElementPadding: {
                if (size < 2)
                    return NO;
                UInt16 pSize = *((UInt16 *) (aData.bytes + idx));
                if (size < 2 + pSize)
                    return NO;

                idx += 2 + pSize;
                size -= 2 + pSize;

                break;
            }
            case ENHeaderElementFileHMAC: {
                if (size < ENCR_HMAC_LEN)
                    return NO;

                item.hmac = [NSData dataWithBytes:(void *) (aData.bytes + idx) length:ENCR_HMAC_LEN];

                idx += ENCR_HMAC_LEN;
                size -= ENCR_HMAC_LEN;

                break;
            }
            case ENHeaderElementLinkDestination: {
                if (size < 2)
                    return NO;
                UInt16 lSize = *((UInt16 *) (aData.bytes + idx));
                if (size < 2 + lSize)
                    return NO;

                NSString *dest = [[NSString alloc] initWithBytes:aData.bytes + idx + 2 length:lSize encoding:NSUTF8StringEncoding];
                if (!dest)
                    return NO;
                item.linkDestination = dest;
                idx += 2 + lSize;
                size -= 2 + lSize;
                break;
            }
            default:
                return NO;
        }
    }

    return YES;
}

- (void)openArchive:(NSString *)archivePath {
    int fd = open([archivePath fileSystemRepresentation], O_RDONLY);
    _inputFd = fd;

    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:startedOperation:)])
        [self.delegate encryptedArchive:self startedOperation:@{kEncryptedArchiveOperation : kEncryptedArchiveOperationOpening}];

    if (fd == -1) {
        NSError *lowError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        [self reportOpenError:ENEncryptedArchiveOpeningFailed lowError:lowError];
        return;
    }

    _archiveOpened = YES;

    struct stat arcStat;
    int res = stat([archivePath fileSystemRepresentation], &arcStat);

    if (res == -1) {
        NSError *lowError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        [self reportOpenError:ENEncryptedArchiveMagicCheckFailed lowError:lowError];
        return;
    }

    _archiveSize = arcStat.st_size;

    /* checking file magic number */

    UInt32 hdr = 0;
    if (![self inputData:&hdr ofSize:4] || (hdr != ENEncryptoHeader)) {
        [self reportOpenError:ENEncryptedArchiveMagicCheckFailed lowError:nil];
        return;
    }

    /* reading directory locator size */

    UInt32 locatorSize = 0;
    lseek(fd, -8, SEEK_END);
    if ((![self inputData:&hdr ofSize:4]) || !([self inputData:&locatorSize ofSize:4]) || (hdr != ENHeaderElementDirLocatorSize) || (locatorSize + 4 > arcStat.st_size)) {
        [self reportOpenError:ENEncryptedArchiveInvalidDirectoryLocatorSize lowError:nil];
        return;
    }

    /* reading directory locator */

    lseek(fd, -(off_t) locatorSize, SEEK_END);
    NSMutableData *locatorData = [NSMutableData new];
    [locatorData setLength:locatorSize];
    if (![self inputData:locatorData.mutableBytes ofSize:locatorSize]) {
        [self reportOpenError:ENEncryptedArchiveInvalidDirectoryLocator lowError:nil];
        return;
    }

    ENEncryptedArchiveDirectoryLocator *locator = [ENEncryptedArchiveDirectoryLocator new];
    if (![locator load:locatorData]) {
        [self reportOpenError:ENEncryptedArchiveInvalidDirectoryLocator lowError:nil];
        return;
    }

    if (locator.version > 0x00000100) {
        [self reportOpenError:ENEncryptedArchiveUnsupportedVersion lowError:nil];
        return;
    }

    self.passwordHint = locator.passwordHint;
    _masterSalt = locator.salt;

    self.encryptFiles = (locator.flags & ENFlagEncryptFiles) != 0;
    self.encryptDirectory = (locator.flags & ENFlagEncryptDirectory) != 0;
    self.compressFiles = (locator.flags & ENFlagCompressFiles) != 0;
    self.calculateFilesHmac = (locator.flags & ENFlagHmacFiles) != 0;
    self.calculateDirectoryHmac = (locator.flags & ENFlagHmacDirectory) != 0;

    UInt8 alg = (locator.flags >> 8) & 0xff;
    if (alg == ENFlagAES128)
        self.AESKeyBits = 128;
    else if (alg == ENFlagAES192)
        self.AESKeyBits = 192;
    else if (alg == ENFlagAES256)
        self.AESKeyBits = 256;
    else {
        [self reportOpenError:ENEncryptedArchiveInvalidEncryptionSettings lowError:nil];
        return;
    }

    if ((self.encryptFiles || self.encryptDirectory) && (!_masterSalt || (_masterSalt.length != ENCR_SALT_LENGTH))) {
        [self reportOpenError:ENEncryptedArchiveInvalidEncryptionSettings lowError:nil];
        return;
    }

    if (self.encryptFiles || self.encryptDirectory) {
        if (!self.password || (self.password.length == 0)) {
            BOOL cancel = NO;
            if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchivePasswordNeeded:cancel:)])
                [self.delegate encryptedArchivePasswordNeeded:self cancel:&cancel];
            else
                cancel = YES;

            if (cancel) {
                [self reportOpenError:ENEncryptedArchiveNoPasswordSpecified lowError:nil];
                return;
            }
        }

        [self deriveMasterKey:NO];
    }

    if (self.encryptDirectory || self.encryptFiles) {
        NSMutableData *encrLocation = self.encryptDirectory ? [NSMutableData dataWithLength:32] : [NSMutableData dataWithLength:16];

        while (1) {
            if (self.encryptDirectory) {
                ((UInt64 *) encrLocation.mutableBytes)[0] = locator.directoryPosition;
                ((UInt64 *) encrLocation.mutableBytes)[1] = locator.directorySize;
                ((UInt64 *) encrLocation.mutableBytes)[2] = locator.reserved1;
                ((UInt64 *) encrLocation.mutableBytes)[3] = locator.reserved2;
            }
            else {
                ((UInt64 *) encrLocation.mutableBytes)[0] = locator.reserved1;
                ((UInt64 *) encrLocation.mutableBytes)[1] = locator.reserved2;
            }

            if (![self cryptWithMaster:encrLocation iv:nil decrypt:YES]) {
                [self reportOpenError:ENEncryptedArchiveDecryptionFailed lowError:nil];
                return;
            }

            UInt64 r1 = self.encryptDirectory ? ((UInt64 *) encrLocation.mutableBytes)[2] : ((UInt64 *) encrLocation.mutableBytes)[0];
            UInt64 r2 = self.encryptDirectory ? ((UInt64 *) encrLocation.mutableBytes)[3] : ((UInt64 *) encrLocation.mutableBytes)[1];

            if ((r1 ^ r2) != ENHeaderElementaDirLocatorR1) {
                BOOL cancel = NO;

                if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchivePasswordNeeded:cancel:)])
                    [self.delegate encryptedArchivePasswordNeeded:self cancel:&cancel];
                else
                    cancel = YES;

                if (cancel) {
                    [self reportOpenError:ENEncryptedArchiveInvalidPassword lowError:nil];
                    return;
                }
                else
                    [self deriveMasterKey:NO];
            }
            else {
                if (self.encryptDirectory) {
                    locator.directoryPosition = ((UInt64 *) encrLocation.mutableBytes)[0];
                    locator.directorySize = ((UInt64 *) encrLocation.mutableBytes)[1];
                    locator.reserved1 = ((UInt64 *) encrLocation.mutableBytes)[2];
                    locator.reserved2 = ((UInt64 *) encrLocation.mutableBytes)[3];
                }
                else {
                    locator.reserved1 = ((UInt64 *) encrLocation.mutableBytes)[0];
                    locator.reserved2 = ((UInt64 *) encrLocation.mutableBytes)[1];
                }
                break;
            }
        }
    }

    // Loading and decrypting preview

    if (locator.preview && (locator.preview.length > 0)) {
        if (self.encryptFiles || self.encryptDirectory) {
            NSMutableData *decrData = [NSMutableData dataWithData:locator.preview];
            [self cryptWithMaster:decrData iv:nil decrypt:YES];
            NSInteger padding = ((unsigned char *) decrData.mutableBytes)[decrData.length - 1];
            if (padding > ENCR_BLOCK_SIZE) {
                [self reportOpenError:ENEncryptedArchiveDecryptionFailed lowError:nil];
                return;
            }

            [decrData setLength:decrData.length - padding];
            self.preview = decrData;
        }
        else
            self.preview = locator.preview;
    }
    else
        self.preview = nil;


    if (locator.directoryPosition + locator.directorySize > arcStat.st_size) {
        [self reportOpenError:ENEncryptedArchiveInvalidDirectoryLocator lowError:nil];
        return;
    }

    lseek(fd, locator.directoryPosition, SEEK_SET);
    UInt64 dirLeft = locator.directorySize;
    UInt32 fldSize = 0;
    NSMutableData *dirData = [NSMutableData new];
    BOOL cancel = NO;

    /* reading directory records */

    if (self.encryptDirectory) {
        if (![self beginInputDecryption:self.calculateDirectoryHmac]) {
            [self reportOpenError:ENEncryptedArchiveDecryptionFailed lowError:nil];
            return;
        }
    }

    while (dirLeft > 0) {
        BOOL hasError = NO;

        if (![self inputData:&hdr ofSize:4] || ![self inputData:&fldSize ofSize:4] || (hdr != ENHeaderDirectory) || (fldSize > dirLeft))
            hasError = YES;
        else {
            [dirData setLength:fldSize];
            if (![self inputData:dirData.mutableBytes ofSize:fldSize])
                hasError = YES;
            else {
                ENEncryptedArchiveItem *anItem = [ENEncryptedArchiveItem new];
                if (![self loadArchiveItem:anItem fromData:dirData])
                    hasError = YES;
                else {
                    if ((anItem.path.length == 0) || (anItem.localHeaderPosition == 0))
                        hasError = YES;
                    else
                        [self addToDirectory:anItem];
                }
            }
        }

        if (hasError) {
            NSError *lowError = NULL;
            if (errno)
                lowError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
            [self reportOpenError:ENEncryptedArchiveInvalidDirectoryRecord lowError:lowError];
            return;
        }

        if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationProgress:cancel:)]) {
            NSMutableDictionary *infoDict = [NSMutableDictionary dictionary];
            infoDict[kEncryptedArchiveOperation] = kEncryptedArchiveOperationOpening;
            infoDict[kEncryptedArchiveTotalProgress] = [NSNumber numberWithDouble:(double) (locator.directorySize - dirLeft) * 100.0f / (double) (locator.directorySize)];
            [self.delegate encryptedArchive:self operationProgress:infoDict cancel:&cancel];

            if (cancel) {
                [self reportOpenError:ENEncryptedArchiveErrorOperationCancelled lowError:nil];
                return;
            }
        }

        dirLeft -= fldSize + 8;
    }

    if (self.encryptDirectory) {
        if (![self endInputDecryption]) {
            [self reportOpenError:ENEncryptedArchiveDecryptionFailed lowError:nil];
            return;
        }

        if (self.calculateDirectoryHmac) {
            if (![_lastHmac isEqualTo:locator.hmac]) {
                ENEncryptedArchiveAction action = ENActionCancel;

                if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:HMACMismatch:action:)])
                    [self.delegate encryptedArchive:self HMACMismatch:nil action:&action];

                if (action == ENActionCancel) {
                    [self reportOpenError:ENEncryptedArchiveErrorDirectoryHMACMismatch lowError:nil];
                    return;
                }
            }
        }
    }

    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationProgress:cancel:)]) {
        NSDictionary *infoDict = @{kEncryptedArchiveTotalProgress : @100.0, kEncryptedArchiveOperation : kEncryptedArchiveOperationOpening};
        [self.delegate encryptedArchive:self operationProgress:infoDict cancel:&cancel];
    }

    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:finishedOperation:)])
        [self.delegate encryptedArchive:self finishedOperation:@{kEncryptedArchiveOperation : kEncryptedArchiveOperationOpening}];
}

- (void)closeArchive {
    _archiveOpened = NO;
    if (_inputFd != -1) {
        close(_inputFd);
        _inputFd = -1;
    }

    [_directory removeAllObjects];
}

- (void)reportExtractError:(int)errorCode forItem:(ENEncryptedArchiveItem *)anItem lowError:(NSError *)lowError {
    if ((self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationError:)])) {
        NSError *error = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:errorCode userInfo:nil];
        NSMutableDictionary *infoDict = [NSMutableDictionary dictionary];
        if (lowError)
            infoDict[kEncryptedArchiveUnderlyingError] = lowError;
        if (anItem)
            infoDict[kEncryptedArchiveItem] = anItem;
        infoDict[kEncryptedArchiveError] = error;
        infoDict[kEncryptedArchiveOperation] = kEncryptedArchiveOperationExtraction;
        [self.delegate encryptedArchive:self operationError:infoDict];
    }
}

- (void)internalSetDirectoryAttributes:(ENEncryptedArchiveItem *)anItem {
    NSError *anError = nil;
    if (![[NSFileManager defaultManager] setAttributes:anItem.attributes ofItemAtPath:anItem.realPath error:&anError]) {
        if (([[anItem.attributes fileOwnerAccountID] shortValue] == 0) || ([[anItem.attributes fileGroupOwnerAccountID] shortValue] == 0))
            NSLog(@"Warning! set root owner/group failed for item %@.", anItem.path);
        else
            NSLog(@"Warning! setAttributes failed for item %@. Attributes %@.", anItem.path, anItem.attributes);
    }

    [ENFileMetadata applyExtendedAttributes:anItem.extendedAttributes toFile:anItem.realPath];
    if (anItem.extendedSecurityOptions)
        [ENFileMetadata applyExtendedSecurityOptions:anItem.extendedSecurityOptions toFile:anItem.realPath];
}

- (BOOL)internalExtractItem:(ENEncryptedArchiveItem *)anItem toPath:(NSString *)aPath error:(NSError **)anError {
    /* reading local file header for extended attributes and possibly other fields */

    off_t res = lseek(_inputFd, anItem.localHeaderPosition, SEEK_SET);
    if (res == -1) {
        if (anError)
            *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveCannotReadLocalHeader userInfo:nil];
        return NO;
    }

    BOOL hasError = NO;
    UInt32 hdr, fldSize;
    NSMutableData *locHeader = [NSMutableData new];

    if (self.encryptFiles) {
        if (![self beginInputDecryption:self.calculateFilesHmac]) {
            if (anError)
                *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveDecryptionFailed userInfo:nil];
            return NO;
        }
    }

    if (![self inputData:&hdr ofSize:4] || ![self inputData:&fldSize ofSize:4] || (hdr != ENHeaderLocalFile) || (anItem.localHeaderPosition + fldSize > _archiveSize))
        hasError = YES;
    else {
        [locHeader setLength:fldSize];
        if (![self inputData:locHeader.mutableBytes ofSize:fldSize]) {
            if (anError)
                *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveCannotReadLocalHeader userInfo:nil];
            return NO;
        }
        else if (![self loadArchiveItem:anItem fromData:locHeader])
            hasError = YES;
    }

    if (hasError) {
        if (anError)
            *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveInvalidLocalHeader userInfo:nil];
        return NO;
    }

    NSString *itemType = [anItem.attributes fileType];

    if ([NSFileTypeRegular isEqualTo:itemType]) {
        int fd = open([aPath fileSystemRepresentation], O_CREAT | O_RDWR, 0600);
        if (fd == -1) {
            if (anError)
                *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveCannotCreateExtractionFile userInfo:nil];
            return NO;
        }

        @try {
            BOOL reportProgress = (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationProgress:cancel:)]);

            long blockSize = OUTPUT_BLOCK_SIZE;
            double total = 0.0f;
            NSMutableData *readBuffer = [[NSMutableData alloc] initWithLength:blockSize];
            NSMutableData *comprBuffer = nil;


            UInt64 totalBytes = anItem.size;
            UInt64 bytesLeft = anItem.compressed ? anItem.compressedSize : totalBytes;
            UInt64 processedBytes = 0;
            UInt64 progressReport = totalBytes / 200; // how often report progress
            UInt64 tillProgressReport = 0;

            if (anItem.compressed) {
                _decompressionStream = malloc(sizeof(z_stream));
                _decompressionStream->zalloc = NULL;
                _decompressionStream->zfree = NULL;
                _decompressionStream->opaque = NULL;
                int ret = inflateInit(_decompressionStream);
                if (ret != Z_OK) {
                    NSLog(@"Warning! inflateInit failed. Error %d", ret);
                    free(_decompressionStream);
                    _decompressionStream = nil;
                    if (anError)
                        *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveDecompressionFailed userInfo:nil];
                    return NO;
                }
                comprBuffer = [[NSMutableData alloc] initWithLength:blockSize];
            }

            while (bytesLeft > 0) {
                if (blockSize > bytesLeft)
                    blockSize = bytesLeft;

                if ([self inputData:readBuffer.mutableBytes ofSize:blockSize]) {
                    if (anItem.compressed) {
                        _decompressionStream->next_in = readBuffer.mutableBytes;
                        _decompressionStream->avail_in = (UInt) blockSize;

                        int inflateRes;

                        do {
                            _decompressionStream->next_out = comprBuffer.mutableBytes;
                            _decompressionStream->avail_out = (UInt) comprBuffer.length;
                            inflateRes = inflate(_decompressionStream, Z_NO_FLUSH);
                            if (inflateRes != Z_OK && inflateRes != Z_STREAM_END && inflateRes != Z_BUF_ERROR) {
                                NSLog(@"Warning! inflate failed. Error %d", inflateRes);
                                if (anError)
                                    *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveDecompressionFailed userInfo:nil];
                                return NO;
                            }

                            if (comprBuffer.length - _decompressionStream->avail_out > 0) {
                                write(fd, comprBuffer.bytes, comprBuffer.length - _decompressionStream->avail_out);
                                processedBytes += comprBuffer.length - _decompressionStream->avail_out;
                            }
                        } while (((_decompressionStream->avail_out == 0) || (bytesLeft == blockSize)) && (inflateRes != Z_STREAM_END));
                    }
                    else {
                        write(fd, readBuffer.bytes, blockSize);
                        processedBytes += blockSize;
                    }

                    bytesLeft -= blockSize;

                    if (reportProgress) {
                        tillProgressReport += blockSize;

                        if (tillProgressReport >= progressReport) {
                            tillProgressReport = 0;
                            total = (double) (_operationProcessed + processedBytes) * 100.f / (double) _operationTotal;
                            double itemProgress = 100.0f * (double) processedBytes / (double) totalBytes;
                            [self reportExtractProgress:itemProgress forItem:anItem totalProgress:total cancel:&_extractionCancelled];

                            if (_extractionCancelled)
                                break;
                        }
                    }
                }
                else {
                    if (anError)
                        *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveItemExtractionFailed userInfo:nil];
                    return NO;
                }
            }

            if (processedBytes != anItem.size) {
                NSLog(@"Warning! Processed size differs from item size for file %@.", anItem.path);
            }
        }
        @finally {
            close(fd);
            if (anItem.compressed && _decompressionStream) {
                inflateEnd(_decompressionStream);
                free(_decompressionStream);
                _decompressionStream = nil;
            }
        }

        if (![[NSFileManager defaultManager] setAttributes:anItem.attributes ofItemAtPath:aPath error:anError]) {
            if (([[anItem.attributes fileOwnerAccountID] shortValue] == 0) || ([[anItem.attributes fileGroupOwnerAccountID] shortValue] == 0))
                NSLog(@"Warning! set root owner/group failed for item %@.", anItem.path);
            else
                NSLog(@"Warning! setAttributes failed for item %@. Attributes %@.", anItem.path, anItem.attributes);
        }

        [ENFileMetadata applyExtendedAttributes:anItem.extendedAttributes toFile:aPath];
        if (anItem.extendedSecurityOptions)
            [ENFileMetadata applyExtendedSecurityOptions:anItem.extendedSecurityOptions toFile:aPath];

        _operationProcessed += anItem.size;
    }
    else if ([NSFileTypeDirectory isEqualTo:itemType]) {
        if (![[NSFileManager defaultManager] createDirectoryAtPath:aPath withIntermediateDirectories:NO attributes:nil error:anError])
            return NO;

        _operationProcessed += anItem.size;
    }
    else if ([NSFileTypeSymbolicLink isEqualTo:itemType]) {
        NSError *error = nil;
        if (![[NSFileManager defaultManager] createSymbolicLinkAtPath:aPath withDestinationPath:anItem.linkDestination error:&error]) {
            if (anError)
                *anError = error;

            return NO;
        }
    }
    else {
        if (anError)
            *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveUnknownItemType userInfo:nil];
        return NO;
    }

    if (self.encryptFiles) {
        if (![self endInputDecryption]) {
            if (anError)
                *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveDecryptionFailed userInfo:nil];
            return NO;
        }
    }

    if (self.calculateFilesHmac) {
        if (![_lastHmac isEqualTo:anItem.hmac]) {
            ENEncryptedArchiveAction action = ENActionCancel;

            if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:HMACMismatch:action:)])
                [self.delegate encryptedArchive:self HMACMismatch:anItem action:&action];

            if (action == ENActionCancel) {
                if (anError)
                    *anError = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:ENEncryptedArchiveHMACCheckFailed userInfo:nil];
                return NO;
            }
        }
    }

    if (!_extractionCancelled) {
        [self reportExtractProgress:100.0f forItem:anItem totalProgress:(double) _operationProcessed * 100.0f / (double) _operationTotal cancel:&_extractionCancelled];

        anItem.realPath = aPath;
        return YES;
    }
    else
        return NO;
}


- (void)reportExtractProgress:(double)itemProgress forItem:(ENEncryptedArchiveItem *)anItem totalProgress:(double)total cancel:(BOOL *)cancel {
    if (cancel)
        *cancel = NO;

    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationProgress:cancel:)]) {
        NSMutableDictionary *infoDict = [NSMutableDictionary dictionary];
        if (anItem)
            infoDict[kEncryptedArchiveItem] = anItem;
        infoDict[kEncryptedArchiveItemProgress] = [NSNumber numberWithDouble:itemProgress];
        infoDict[kEncryptedArchiveTotalProgress] = [NSNumber numberWithDouble:total];
        infoDict[kEncryptedArchiveOperation] = kEncryptedArchiveOperationExtraction;

        [self.delegate encryptedArchive:self operationProgress:infoDict cancel:cancel];
    }
}

- (void)extractAllItems:(NSString *)aPath {
    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:startedOperation:)])
        [self.delegate encryptedArchive:self startedOperation:@{kEncryptedArchiveOperation : kEncryptedArchiveOperationExtraction}];

    if (!_archiveOpened) {
        [self reportExtractError:ENEncryptedArchiveArchiveNotOpened forItem:nil lowError:nil];
        return;
    }

    BOOL isDir = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:aPath isDirectory:&isDir] || !isDir) {
        [self reportExtractError:ENEncryptedArchiveNoOutputDirectory forItem:nil lowError:nil];
        return;
    }

    NSMutableDictionary *extracted = [NSMutableDictionary new];
    NSMutableArray *extractParents = [NSMutableArray new];
    NSError *extractError = nil;

    _operationProcessed = 0;
    _operationTotal = 0;
    _extractionCancelled = NO;

    for (ENEncryptedArchiveItem *anItem in [_directory allValues])
        _operationTotal += anItem.size;

    [self reportExtractProgress:0.0f forItem:nil totalProgress:0.0f cancel:&_extractionCancelled];
    if (_extractionCancelled) {
        [self reportExtractError:ENEncryptedArchiveErrorOperationCancelled forItem:nil lowError:nil];
        return;
    }

    for (ENEncryptedArchiveItem *anItem in [_directory allValues]) {
        @autoreleasepool {
            if (!extracted[anItem.path.lowercaseString]) {
                [extractParents addObject:anItem];
                /* checking if parent directory was extracted */
                NSString *parentPath = [anItem.path stringByDeletingLastPathComponent];
                while ((parentPath.length > 1) && !extracted[parentPath.lowercaseString]) {
                    ENEncryptedArchiveItem *parItem = [self recordAtPath:[parentPath lowercaseString]];
                    if (!parItem) {
                        NSLog(@"Warning! Archive error : invalid tree structure, no parent folder for %@", anItem.path);
                        break;
                    }

                    [extractParents addObject:parItem];
                    parentPath = [parentPath stringByDeletingLastPathComponent];
                }

                /* extracting parent directories if any and item after that */
                for (ENEncryptedArchiveItem *parItem in [extractParents reverseObjectEnumerator]) {
                    if (![self internalExtractItem:parItem toPath:[aPath stringByAppendingPathComponent:parItem.path] error:&extractError]) {
                        if (!_extractionCancelled)
                            [self reportExtractError:ENEncryptedArchiveItemExtractionFailed forItem:parItem lowError:extractError];
                        else
                            [self reportExtractError:ENEncryptedArchiveErrorOperationCancelled forItem:parItem lowError:nil];

                        return;
                    }
                    extracted[parItem.path.lowercaseString] = parItem;
                }

                for (ENEncryptedArchiveItem *anItem in extractParents) {
                    if ([NSFileTypeDirectory isEqualTo:anItem.attributes.fileType] && anItem.realPath)
                        [self internalSetDirectoryAttributes:anItem];
                }

                [extractParents removeAllObjects];
            }
        }
    }

    [self reportExtractProgress:100.0f forItem:nil totalProgress:100.0f cancel:&_extractionCancelled];

    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:finishedOperation:)])
        [self.delegate encryptedArchive:self finishedOperation:@{kEncryptedArchiveOperation : kEncryptedArchiveOperationExtraction}];
}

- (BOOL)deriveMasterKey:(BOOL)generateSalt {
    NSData *pswdData = [self.password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *salt;

    if (generateSalt) {
        NSMutableData *newSalt = [NSMutableData dataWithLength:ENCR_SALT_LENGTH];
        SecRandomCopyBytes(kSecRandomDefault, newSalt.length, newSalt.mutableBytes);
        salt = newSalt;
    }
    else
        salt = _masterSalt;

    int keySize;
    if (self.AESKeyBits <= 128)
        keySize = 16;
    else if (self.AESKeyBits <= 192)
        keySize = 24;
    else
        keySize = 32;

    NSMutableData *key = [NSMutableData dataWithLength:keySize];
    if (CCKeyDerivationPBKDF(kCCPBKDF2, pswdData.bytes, pswdData.length, salt.bytes, salt.length, kCCPRFHmacAlgSHA256, ENCR_PBKDF2_ROUNDS, key.mutableBytes, keySize) != kCCSuccess)
        return NO;
    else {
        _masterKey = key;
        if (generateSalt)
            _masterSalt = salt;

        return YES;
    }
}

- (BOOL)cryptWithMaster:(NSMutableData *)aData iv:(NSData *)iv decrypt:(BOOL)decrypt {
    // for empty iv using one filled with zeroes
    if (!iv)
        iv = [NSMutableData dataWithLength:ENCR_BLOCK_SIZE];

    CCCryptorRef cryptor;
    if (CCCryptorCreateWithMode(decrypt ? kCCDecrypt : kCCEncrypt, kCCModeCBC, kCCAlgorithmAES, ccNoPadding, iv.bytes, _masterKey.bytes, _masterKey.length, NULL, 0, 0, 0, &cryptor) != kCCSuccess)
        return NO;

    @try {
        size_t dataOut;
        CCCryptorStatus status = CCCryptorUpdate(cryptor, aData.bytes, aData.length, aData.mutableBytes, aData.length, &dataOut);
        if (status != kCCSuccess) {
            NSLog(@"Warning! CCCryptorUpdate failed: %d", status);
            return NO;
        }

        size_t dataLeft;
        status = CCCryptorFinal(cryptor, aData.mutableBytes + dataOut, aData.length - dataOut, &dataLeft);
        if (status != kCCSuccess) {
            NSLog(@"Warning! CCCryptorFinal failed: %d", status);
            return NO;
        }

        [aData setLength:dataOut + dataLeft];
    }
    @finally {
        CCCryptorRelease(cryptor);
    }

    return YES;
}

- (int)keySizeInBytes {
    if (self.AESKeyBits <= 128)
        return 16;
    else if (self.AESKeyBits <= 192)
        return 24;
    else
        return 32;
}

- (BOOL)beginOutputEncryption:(BOOL)hmac {
    int keySize = [self keySizeInBytes];

    /* generating session key and iv */

    NSMutableData *iv = [NSMutableData dataWithLength:ENCR_BLOCK_SIZE];
    SecRandomCopyBytes(kSecRandomDefault, iv.length, iv.mutableBytes);
    NSMutableData *key = [NSMutableData dataWithLength:keySize];
    if (keySize == 24)
        [key setLength:32];
    SecRandomCopyBytes(kSecRandomDefault, key.length, key.mutableBytes);

    /* encrypting session key and iv with master key and zeroed iv */

    NSMutableData *cryptData;
    if (hmac) {
        _calculatingHmac = YES;
        cryptData = [NSMutableData dataWithData:[self createHmacKey]];
        [self initHmac:cryptData];
        [cryptData appendData:iv];
        [cryptData appendData:key];

        CCHmacUpdate(&_hmac, iv.bytes, iv.length);
        CCHmacUpdate(&_hmac, key.bytes, key.length);
    }
    else {
        _calculatingHmac = NO;
        cryptData = [NSMutableData dataWithBytes:iv.bytes length:iv.length];
        [cryptData appendData:key];
    }

    if (![self cryptWithMaster:cryptData iv:nil decrypt:NO])
        return NO;

    [self outputData:cryptData.bytes ofSize:cryptData.length];

    /* creating crypto */

    CCCryptorRef cryptor;
    if (CCCryptorCreateWithMode(kCCEncrypt, kCCModeCBC, kCCAlgorithmAES, ccPKCS7Padding, iv.bytes, key.bytes, key.length, NULL, 0, 0, 0, &cryptor) != kCCSuccess)
        return NO;

    _outputCrypto = cryptor;
    _outputCryptoCache = [NSMutableData dataWithLength:OUTPUT_BLOCK_SIZE];

    return YES;
}

- (BOOL)endOutputEncryption:(BOOL)hmac {
    if (_outputCrypto) {
        size_t sz = CCCryptorGetOutputLength(_outputCrypto, 0, YES);
        if (_outputCryptoCache.length < sz)
            [_outputCryptoCache setLength:sz];

        size_t dataOut;
        CCCryptorStatus status = CCCryptorFinal(_outputCrypto, _outputCryptoCache.mutableBytes, _outputCryptoCache.length, &dataOut);

        if (status != kCCSuccess) {
            NSLog(@"Warning! CCCryptorFinal failed. Error %d.", status);
            return NO;
        }
        else {
            if (_calculatingHmac) {
                _lastHmac = [self finishHmac];
                _calculatingHmac = NO;
            }

            if (dataOut > 0) {
                size_t res = write(_archiveFileFd, _outputCryptoCache.mutableBytes, dataOut);
                if (res == -1) {
                    NSLog(@"Warning! Writing to archive file failed. Error %d", errno);
                    return NO;
                }
            }

            CCCryptorRelease(_outputCrypto);
            _outputCrypto = nil;
            _outputCryptoCache = nil;
        }
    }

    return YES;
}

- (BOOL)beginInputDecryption:(BOOL)hmac {
    int keySize = [self keySizeInBytes];

    /* reading session key and iv */

    NSMutableData *keyAndIV = [NSMutableData dataWithLength:ENCR_BLOCK_SIZE + keySize];
    if (keySize == 24)
        [keyAndIV setLength:48];
    if (hmac)
        [keyAndIV setLength:keyAndIV.length + ENCR_HMAC_KEY_LEN];

    if (![self inputData:keyAndIV.mutableBytes ofSize:keyAndIV.length])
        return NO;

    /* decrypting session key and iv with master key and zeroed iv */

    if (![self cryptWithMaster:keyAndIV iv:nil decrypt:YES])
        return NO;

    NSData *iv, *key;

    if (hmac) {
        _calculatingHmac = YES;
        NSData *hmacKey = [NSData dataWithBytes:keyAndIV.bytes length:ENCR_HMAC_KEY_LEN];
        iv = [NSData dataWithBytes:keyAndIV.bytes + ENCR_HMAC_KEY_LEN length:ENCR_BLOCK_SIZE];
        key = [NSData dataWithBytes:keyAndIV.bytes + ENCR_HMAC_KEY_LEN + ENCR_BLOCK_SIZE length:keySize];

        [self initHmac:hmacKey];
        CCHmacUpdate(&_hmac, keyAndIV.bytes + ENCR_HMAC_KEY_LEN, keyAndIV.length - ENCR_HMAC_KEY_LEN);
    }
    else {
        _calculatingHmac = NO;
        iv = [NSData dataWithBytes:keyAndIV.bytes length:ENCR_BLOCK_SIZE];
        key = [NSData dataWithBytes:keyAndIV.bytes + ENCR_BLOCK_SIZE length:keySize];
    }

    /* creating crypto */

    CCCryptorRef cryptor;
    if (CCCryptorCreateWithMode(kCCDecrypt, kCCModeCBC, kCCAlgorithmAES, ccNoPadding, iv.bytes, key.bytes, key.length, NULL, 0, 0, 0, &cryptor) != kCCSuccess)
        return NO;

    _inputCrypto = cryptor;
    _inputCryptoCache = [NSMutableData dataWithLength:OUTPUT_BLOCK_SIZE];
    _inputDecryptedCache = [NSMutableData new];

    return YES;
}

- (BOOL)endInputDecryption {
    size_t dataOut;
    CCCryptorStatus status = CCCryptorFinal(_inputCrypto, _inputCryptoCache.mutableBytes, _inputCryptoCache.length, &dataOut);

    if (status != kCCSuccess) {
        NSLog(@"Warning! Decryption CCCryptorFinal failed. Error %d.", status);
        return NO;
    }
    else {
        if (_calculatingHmac) {
            _lastHmac = [self finishHmac];
            _calculatingHmac = NO;
        }

        CCCryptorRelease(_inputCrypto);
        _inputCrypto = nil;
        _inputCryptoCache = nil;
        _inputDecryptedCache = nil;
        return YES;
    }
}

- (void)initHmac:(NSData *)hmacKey {
    CCHmacInit(&_hmac, kCCHmacAlgSHA256, hmacKey.bytes, hmacKey.length);
}

- (NSData *)finishHmac {
    NSMutableData *hmac = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CCHmacFinal(&_hmac, hmac.mutableBytes);
    return hmac;
}

- (NSData *)createHmacKey {
    NSMutableData *key = [NSMutableData dataWithLength:ENCR_HMAC_KEY_LEN];
    SecRandomCopyBytes(kSecRandomDefault, key.length, key.mutableBytes);
    return key;
}

- (void)outputData:(const void *)data ofSize:(NSUInteger)size {
    if (_archiveFileFd != -1) {
        if (!_outputCrypto) {
            size_t res = write(_archiveFileFd, data, size);
            if (res == -1)
                NSLog(@"Warning! Writing to archive file failed. Error %d", errno);
        }
        else {
            if (_outputCryptoCache.length < size + 16)
                [_outputCryptoCache setLength:size + 16];

            size_t dataOut;
            CCCryptorStatus status = CCCryptorUpdate(_outputCrypto, data, size, _outputCryptoCache.mutableBytes, _outputCryptoCache.length, &dataOut);

            if (status != kCCSuccess) {
                NSLog(@"Warning! CCCryptorUpdate in outputData: failed: %d", status);
                return;
            }
            else {
                if (_calculatingHmac)
                    CCHmacUpdate(&_hmac, data, size);

                if (dataOut > 0) {
                    size_t res = write(_archiveFileFd, _outputCryptoCache.mutableBytes, dataOut);
                    if (res == -1)
                        NSLog(@"Warning! Writing to archive file failed. Error %d", errno);
                }
            }
        }
    }
}

- (void)cleanupOutput {
    if (_archiveFileFd != -1) {
        close(_archiveFileFd);
        [[NSFileManager defaultManager] removeItemAtPath:_archiveFilePath error:nil];
        _archiveFileFd = -1;
        _archiveFilePath = nil;
        if (_compressionStream) {
            deflateEnd(_compressionStream);
            free(_compressionStream);
            _compressionStream = NULL;
        }
        _calculatingHmac = NO;
    }
}

- (void)reportSaveError:(int)errorCode forItem:(ENEncryptedArchiveItem *)anItem lowError:(NSError *)lowError {
    if ((self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationError:)])) {
        NSError *error = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain code:errorCode userInfo:nil];
        NSMutableDictionary *infoDict = [NSMutableDictionary dictionary];
        if (anItem)
            infoDict[kEncryptedArchiveItem] = anItem;
        if (lowError)
            infoDict[kEncryptedArchiveUnderlyingError] = lowError;
        infoDict[kEncryptedArchiveError] = error;
        infoDict[kEncryptedArchiveOperation] = kEncryptedArchiveOperationSaving;


        [self.delegate encryptedArchive:self operationError:infoDict];
    }
}

- (void)reportSaveProgress:(double)itemProgress forItem:(ENEncryptedArchiveItem *)anItem totalProgress:(UInt64)total cancel:(BOOL *)cancel {
    *cancel = NO;

    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationProgress:cancel:)]) {
        NSMutableDictionary *infoDict = [NSMutableDictionary dictionary];
        if (anItem)
            infoDict[kEncryptedArchiveItem] = anItem;
        infoDict[kEncryptedArchiveItemProgress] = @(itemProgress);
        infoDict[kEncryptedArchiveTotalProgress] = @(_operationTotal ? (double) total * 100.0 / (double) _operationTotal : 100.0);

        [self.delegate encryptedArchive:self operationProgress:infoDict cancel:cancel];
    }
}

- (NSMutableData *)writeCommonHeaderFields:(ENEncryptedArchiveItem *)anItem {
    // Common fields go in the following order:
    // file type : 1 byte
    // file size : 8 bytes
    // posix permissions : 2 bytes
    // owner id : 2 bytes
    // group id : 2 bytes    
    // creation time : 8 bytes (int64 timestamp)
    // modification time : 8 bytes (int64 timestamp)
    // UTI [2 bytes length; and length bytes after it]
    // path [2 bytes length; and length bytes after it]

    NSMutableData *res = [NSMutableData new];

    // File Type
    NSString *fType = [anItem.attributes fileType];
    if (fType) {
        [res appendBytes:&ENHeaderElementFileType length:4];
        UInt8 fTypeBt = ENHeaderFileTypeRegular;
        if ([fType isEqualToString:NSFileTypeDirectory])
            fTypeBt = ENHeaderFileTypeDirectory;
        else if ([fType isEqualToString:NSFileTypeSymbolicLink])
            fTypeBt = ENHeaderFileTypeSymLink;

        [res appendBytes:&fTypeBt length:1];
    }

    // File flags
    UInt32 flg = 0;
    if (anItem.compressed)
        flg = flg | ENFlagCompressFiles;
    [res appendBytes:&ENHeaderElementFileFlags length:4];
    [res appendBytes:&flg length:4];

    // File Size
    UInt64 fSize = [anItem.attributes fileSize];
    [res appendBytes:&ENHeaderElementFileSize length:4];
    [res appendBytes:&fSize length:8];

    // Posix Permissions
    UInt16 permissions = [anItem.attributes filePosixPermissions];
    [res appendBytes:&ENHeaderElementFilePerm length:4];
    [res appendBytes:&permissions length:2];

    // owner account id
    NSNumber *ownerId = [anItem.attributes fileOwnerAccountID];
    if (ownerId) {
        UInt16 oid = [ownerId shortValue];
        [res appendBytes:&ENHeaderElementFileOwner length:4];
        [res appendBytes:&oid length:2];
    }

    // owner group id
    NSNumber *groupId = [anItem.attributes fileGroupOwnerAccountID];
    if (groupId) {
        UInt16 gid = [groupId shortValue];
        [res appendBytes:&ENHeaderElementFileGroup length:4];
        [res appendBytes:&gid length:2];
    }

    // creation time
    NSDate *cTime = [anItem.attributes fileCreationDate];
    if (cTime) {
        // number of milliseconds since reference date
        UInt64 tm = round([cTime timeIntervalSince1970] * 1000);
        [res appendBytes:&ENHeaderElementFileCDat length:4];
        [res appendBytes:&tm length:8];
    }

    // modification time
    NSDate *mTime = [anItem.attributes fileModificationDate];
    if (mTime) {
        // number of milliseconds since reference date
        UInt64 tm = round([mTime timeIntervalSince1970] * 1000);
        [res appendBytes:&ENHeaderElementFileMDat length:4];
        [res appendBytes:&tm length:8];
    }

    // UTI
    NSString *uti = anItem.UTI;
    if (uti && (uti.length > 0)) {
        NSData *str = [uti dataUsingEncoding:NSUTF8StringEncoding];
        UInt16 len;
        if (str.length > 0xffff) {
            str = [NSData dataWithBytes:(void *) str.bytes length:0xffff];
            len = 0xffff;
        }
        else
            len = (UInt16) str.length;
        [res appendBytes:&ENHeaderElementFileUTI length:4];
        [res appendBytes:&len length:2];
        [res appendBytes:str.bytes length:len];
    }

    // Path
    NSString *path = anItem.path;
    if (path && (path.length > 0)) {
        NSData *str = [path dataUsingEncoding:NSUTF8StringEncoding];
        UInt16 len;
        if (str.length > 0xffff) {
            str = [NSData dataWithBytes:(void *) str.bytes length:0xffff];
            len = 0xffff;
        }
        else
            len = (UInt16) str.length;
        [res appendBytes:&ENHeaderElementFilePath length:4];
        [res appendBytes:&len length:2];
        [res appendBytes:str.bytes length:len];
    }
    else
        return nil;

    return res;
}

- (NSMutableData *)writePaddingFieldForSize:(NSUInteger)size {
    if ((size % ENCR_BLOCK_SIZE) != 0) {
        NSUInteger sz = size + 6;
        NSUInteger padSize = ENCR_BLOCK_SIZE - sz % ENCR_BLOCK_SIZE;

        NSMutableData *padData = [NSMutableData dataWithLength:padSize];
        arc4random_buf(padData.mutableBytes, padSize);

        UInt16 pad16 = (UInt16) padSize;

        NSMutableData *fields = [NSMutableData new];
        [fields appendBytes:&ENHeaderElementPadding length:4];
        [fields appendBytes:&pad16 length:2];
        [fields appendData:padData];
        return fields;
    }
    else
        return nil;
}

- (BOOL)saveLocalHeader:(ENEncryptedArchiveItem *)anItem {
    // Building header: first writing common data with central header fields

    NSMutableData *fields = [self writeCommonHeaderFields:anItem];
    if (!fields)
        return NO;

    // Writing extended attributes
    if (anItem.extendedAttributes.count > 0) {
        NSData *exAttrs = [NSKeyedArchiver archivedDataWithRootObject:anItem.extendedAttributes];
        [fields appendBytes:&ENHeaderElementExAttrs length:4];
        UInt32 exAttrLen = (UInt32) exAttrs.length;
        [fields appendBytes:&exAttrLen length:4];
        [fields appendData:exAttrs];
    }

    // Writing extended security options
    if (anItem.extendedSecurityOptions && (anItem.extendedSecurityOptions.length > 0)) {
        [fields appendBytes:&ENHeaderElementExSecOptions length:4];
        UInt32 exLen = (UInt32) anItem.extendedSecurityOptions.length;
        [fields appendBytes:&exLen length:4];
        [fields appendData:anItem.extendedSecurityOptions];
    }

    // Link destination
    if ([NSFileTypeSymbolicLink isEqualTo:[anItem.attributes fileType]]) {
        NSData *str = [anItem.linkDestination dataUsingEncoding:NSUTF8StringEncoding];
        UInt16 len;
        if (str.length > 0xffff) {
            str = [NSData dataWithBytes:(void *) str.bytes length:0xffff];
            len = 0xffff;
        }
        else
            len = (UInt16) str.length;

        [fields appendBytes:&ENHeaderElementLinkDestination length:4];
        [fields appendBytes:&len length:2];
        [fields appendBytes:str.bytes length:len];
    }

    // Adding padding
    if (self.encryptDirectory) {
        NSMutableData *padding = [self writePaddingFieldForSize:fields.length + 8];
        if (padding)
            [fields appendBytes:padding.bytes length:padding.length];
    }

    if (fields.length > 0xffffffff) // just in case
        return NO;

    [self outputData:(void *) &ENHeaderLocalFile ofSize:4];
    UInt32 len = (UInt32) fields.length;
    [self outputData:(void *) &len ofSize:4];
    [self outputData:fields.bytes ofSize:fields.length];

    return YES;
}

- (BOOL)saveCentralHeader:(ENEncryptedArchiveItem *)anItem {
    NSMutableData *fields = [self writeCommonHeaderFields:anItem];
    if (!fields)
        return NO;

    // Adding local header position field
    [fields appendBytes:&ENHeaderElementFileLocator length:4];
    UInt64 pos = anItem.localHeaderPosition;
    [fields appendBytes:&pos length:8];

    // Adding hmac field if present
    if (self.calculateFilesHmac) {
        if (!anItem.hmac || (anItem.hmac.length != ENCR_HMAC_LEN)) {
            NSLog(@"Warning! Invalid HMAC calculated.");
            return NO;
        }

        [fields appendBytes:&ENHeaderElementFileHMAC length:4];
        [fields appendBytes:anItem.hmac.bytes length:ENCR_HMAC_LEN];
    }

    // Writing compressed size
    if (anItem.compressed) {
        [fields appendBytes:&ENHeaderElementFileCSize length:4];
        UInt64 cSize = anItem.compressedSize;
        [fields appendBytes:&cSize length:8];
    }

    // Adding padding
    if (self.encryptDirectory) {
        NSMutableData *padding = [self writePaddingFieldForSize:fields.length + 8];
        if (padding)
            [fields appendBytes:padding.bytes length:padding.length];
    }

    if (fields.length > 0xffffffff) // just in case
        return NO;

    [self outputData:(void *) &ENHeaderDirectory ofSize:4];
    UInt32 len = (UInt32) fields.length;
    [self outputData:(void *) &len ofSize:4];
    [self outputData:fields.bytes ofSize:fields.length];
    _directorySize += 8 + fields.length;

    return YES;
}

- (void)save:(NSString *)outPath {
    BOOL reportProgress = (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:operationProgress:cancel:)]);

    _archiveFilePath = outPath;

    int arcFd = open([outPath fileSystemRepresentation], O_CREAT | O_RDWR, 0600);

    if (arcFd == -1) {
        NSError *lowError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        [self reportSaveError:ENEncryptedArchiveFileCreationFailed forItem:nil lowError:lowError];
        return;
    }

    _archiveFileFd = arcFd;
    BOOL cancel = NO;

    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:startedOperation:)])
        [self.delegate encryptedArchive:self startedOperation:@{kEncryptedArchiveOperation : kEncryptedArchiveOperationSaving}];

    // Writing header
    [self outputData:(void *) &ENEncryptoHeader ofSize:4];

    long currentItem = 0;
    //long itemCount = _directory.count;
    long blockSize = OUTPUT_BLOCK_SIZE;
    //double total;
    NSMutableData *readBuffer = [[NSMutableData alloc] initWithLength:blockSize];
    NSMutableData *comprBuffer = nil;
    if (self.compressFiles)
        comprBuffer = [[NSMutableData alloc] initWithLength:blockSize];

    if (self.encryptDirectory || self.encryptFiles) {
        if (!self.password)
            self.password = @"";

        [self deriveMasterKey:YES];
    }

    _operationTotal = 0;
    _operationProcessed = 0;
    for (ENEncryptedArchiveItem *anItem in [_directory allValues])
        _operationTotal += anItem.size;

    // Writing files
    for (ENEncryptedArchiveItem *anItem in [_directory allValues]) {
        @autoreleasepool {
            anItem.localHeaderPosition = lseek(_archiveFileFd, 0, SEEK_CUR);

            if (!cancel && reportProgress) {
                [self reportSaveProgress:0.0f forItem:anItem totalProgress:_operationProcessed cancel:&cancel];
            }

            if (cancel) {
                [self reportSaveError:ENEncryptedArchiveErrorOperationCancelled forItem:anItem lowError:nil];
                [self cleanupOutput];
                return;
            }

            // writing header

            if (self.encryptFiles) {
                if (![self beginOutputEncryption:self.calculateFilesHmac]) {
                    [self reportSaveError:ENEncryptedArchiveEncryptionFailed forItem:anItem lowError:nil];
                    [self cleanupOutput];
                    return;
                }
            }

            if (![self saveLocalHeader:anItem]) {
                [self reportSaveError:ENEncryptedArchiveLocalHeaderCreationFailed forItem:anItem lowError:nil];
                [self cleanupOutput];
                return;
            }

            // writing file data
            if ([anItem.attributes.fileType isEqualTo:NSFileTypeRegular]) {
                int fd = open([anItem.realPath fileSystemRepresentation], O_RDONLY);

                if (fd == -1) {
                    NSError *lowError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
                    [self reportSaveError:ENEncryptedArchiveFileOpeningFailed forItem:anItem lowError:lowError];
                    [self cleanupOutput];
                    return;
                }

                UInt64 totalBytes = [anItem.attributes fileSize];
                UInt64 bytesLeft = totalBytes;
                UInt64 progressReport = bytesLeft / 100; // how often report progress
                UInt64 tillProgressReport = 0;
                UInt64 compressedSize = 0;

                if (anItem.compressed) {
                    _compressionStream = malloc(sizeof(z_stream));
                    _compressionStream->zalloc = NULL;
                    _compressionStream->zfree = NULL;
                    _compressionStream->opaque = NULL;
                    int ret = deflateInit(_compressionStream, self.compressionLevel);
                    if (ret != Z_OK) {
                        NSLog(@"Warning! deflateInit failed. Error %d", ret);
                        [self reportSaveError:ENEncryptedArchiveCompressionFailed forItem:anItem lowError:nil];
                        free(_compressionStream);
                        _compressionStream = nil;
                        [self cleanupOutput];
                        return;
                    }
                }

                while (bytesLeft > 0) {
                    ssize_t rd = read(fd, readBuffer.mutableBytes, blockSize);
                    if (rd > 0) {
                        if (anItem.compressed) {
                            int flush = bytesLeft == rd ? Z_FINISH : Z_NO_FLUSH;
                            _compressionStream->next_in = readBuffer.mutableBytes;
                            _compressionStream->avail_in = (uInt) rd;

                            do {
                                _compressionStream->next_out = comprBuffer.mutableBytes;
                                _compressionStream->avail_out = (uInt) comprBuffer.length;

                                int ret = deflate(_compressionStream, flush);
                                if ((ret != Z_OK) && (ret != Z_STREAM_END)) {
                                    NSLog(@"Warning! deflate failed. Error %d", ret);
                                    [self reportSaveError:ENEncryptedArchiveCompressionFailed forItem:anItem lowError:nil];
                                    [self cleanupOutput];
                                    return;
                                }
                                [self outputData:comprBuffer.mutableBytes ofSize:comprBuffer.length - _compressionStream->avail_out];
                                compressedSize += comprBuffer.length - _compressionStream->avail_out;
                            } while (_compressionStream->avail_out == 0);
                        }
                        else {
                            [self outputData:readBuffer.mutableBytes ofSize:rd];
                            compressedSize += rd;
                        }

                        bytesLeft -= rd;

                        if (reportProgress) {
                            tillProgressReport += rd;

                            if (tillProgressReport >= progressReport) {
                                tillProgressReport = 0;
                                double itemProgress = 100.0f * (double) (totalBytes - bytesLeft) / (double) totalBytes;
                                [self reportSaveProgress:itemProgress forItem:anItem totalProgress:_operationProcessed + totalBytes - bytesLeft cancel:&cancel];

                                if (cancel) {
                                    [self reportSaveError:ENEncryptedArchiveErrorOperationCancelled forItem:anItem lowError:nil];
                                    close(fd);
                                    [self cleanupOutput];
                                    return;
                                }
                            }
                        }
                    }
                    else if (rd == -1) {
                        NSError *lowError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
                        [self reportSaveError:ENEncryptedArchiveFileReadingFailed forItem:anItem lowError:lowError];
                        close(fd);
                        [self cleanupOutput];
                        return;
                    }
                    else
                        break;
                }

                close(fd);

                if (anItem.compressed) {
                    deflateEnd(_compressionStream);
                    free(_compressionStream);
                    _compressionStream = NULL;
                    anItem.compressedSize = compressedSize;
                }
            }

            if (self.encryptFiles) {
                if (![self endOutputEncryption:self.calculateFilesHmac]) {
                    [self reportSaveError:ENEncryptedArchiveEncryptionFailed forItem:anItem lowError:nil];
                    [self cleanupOutput];
                    return;
                }

                if (self.calculateFilesHmac)
                    anItem.hmac = _lastHmac;
            }

            currentItem++;

            _operationProcessed += anItem.size;
            [self reportSaveProgress:100.0f forItem:anItem totalProgress:_operationProcessed cancel:&cancel];
        }
    }

    // Writing directory

    UInt64 cdirPosition = lseek(_archiveFileFd, 0, SEEK_CUR);
    _directorySize = 0;

    if (self.encryptDirectory) {
        if (![self beginOutputEncryption:self.calculateDirectoryHmac]) {
            [self reportSaveError:ENEncryptedArchiveEncryptionFailed forItem:nil lowError:nil];
            [self cleanupOutput];
            return;
        }
    }

    for (ENEncryptedArchiveItem *anItem in [_directory allValues]) {
        if (![self saveCentralHeader:anItem]) {
            [self reportSaveError:ENEncryptedArchiveDirectoryHeaderCreationFailed forItem:anItem lowError:nil];
            [self cleanupOutput];
            return;
        }
    }

    if (self.encryptDirectory) {
        if (![self endOutputEncryption:self.calculateDirectoryHmac]) {
            [self reportSaveError:ENEncryptedArchiveEncryptionFailed forItem:nil lowError:nil];
            [self cleanupOutput];
            return;
        }
    }

    //UInt64 cdirSize = lseek(_archiveFileFd, 0, SEEK_CUR) - cdirPosition;

    // Writing directory locator

    UInt32 flg = 0;
    if (self.encryptFiles)
        flg = flg | ENFlagEncryptFiles;
    if (self.compressFiles)
        flg = flg | ENFlagCompressFiles;
    if (self.encryptDirectory)
        flg = flg | ENFlagEncryptDirectory;
    if (self.calculateDirectoryHmac)
        flg = flg | ENFlagHmacDirectory;
    if (self.calculateFilesHmac)
        flg = flg | ENFlagHmacFiles;

    if (self.AESKeyBits <= 128)
        flg = flg | (ENFlagAES128 << 8);
    else if (self.AESKeyBits <= 192)
        flg = flg | (ENFlagAES192 << 8);
    else
        flg = flg | (ENFlagAES256 << 8);

    ENEncryptedArchiveDirectoryLocator *locator = [ENEncryptedArchiveDirectoryLocator new];

    locator.directoryPosition = cdirPosition;
    locator.directorySize = _directorySize;

    if (self.encryptDirectory || self.encryptFiles) {
        UInt64 seed = 0;
        SecRandomCopyBytes(kSecRandomDefault, 8, (uint8_t *) &seed);
        locator.reserved1 = ENHeaderElementaDirLocatorR1 ^ seed;
        locator.reserved2 = seed;
        locator.salt = _masterSalt;
    }
    else {
        locator.reserved1 = 0;
        locator.reserved2 = 0;
    }

    if (self.calculateDirectoryHmac)
        locator.hmac = _lastHmac;

    /* encrypting locator fields */

    if (self.encryptDirectory) {
        NSMutableData *encrLocation = [NSMutableData dataWithLength:32];
        ((UInt64 *) encrLocation.mutableBytes)[0] = locator.directoryPosition;
        ((UInt64 *) encrLocation.mutableBytes)[1] = locator.directorySize;
        ((UInt64 *) encrLocation.mutableBytes)[2] = locator.reserved1;
        ((UInt64 *) encrLocation.mutableBytes)[3] = locator.reserved2;

        if (![self cryptWithMaster:encrLocation iv:nil decrypt:NO]) {
            [self reportSaveError:ENEncryptedArchiveDirectoryEncryptionFailed forItem:nil lowError:nil];
            [self cleanupOutput];
            return;
        }

        locator.directoryPosition = ((UInt64 *) encrLocation.mutableBytes)[0];
        locator.directorySize = ((UInt64 *) encrLocation.mutableBytes)[1];
        locator.reserved1 = ((UInt64 *) encrLocation.mutableBytes)[2];
        locator.reserved2 = ((UInt64 *) encrLocation.mutableBytes)[3];
    }
    else if (self.encryptFiles) {
        NSMutableData *encrLocation = [NSMutableData dataWithLength:16];
        ((UInt64 *) encrLocation.mutableBytes)[0] = locator.reserved1;
        ((UInt64 *) encrLocation.mutableBytes)[1] = locator.reserved2;

        if (![self cryptWithMaster:encrLocation iv:nil decrypt:NO]) {
            [self reportSaveError:ENEncryptedArchiveDirectoryEncryptionFailed forItem:nil lowError:nil];
            [self cleanupOutput];
            return;
        }

        locator.reserved1 = ((UInt64 *) encrLocation.mutableBytes)[0];
        locator.reserved2 = ((UInt64 *) encrLocation.mutableBytes)[1];
    }

    locator.flags = flg;
    locator.version = 0x00000100;
    locator.passwordHint = self.passwordHint;

    if (self.preview && (self.preview.length > 0)) {
        if (self.encryptDirectory || self.encryptFiles) {
            /* manually adding PKCS#7 padding */

            NSInteger paddingSize = ENCR_BLOCK_SIZE - (self.preview.length % ENCR_BLOCK_SIZE);
            if (paddingSize == 0)
                paddingSize = ENCR_BLOCK_SIZE;

            NSMutableData *paddedData = [NSMutableData dataWithBytes:self.preview.bytes length:self.preview.length];
            [paddedData setLength:self.preview.length + paddingSize];
            for (int i = 0; i < paddingSize; i++)
                ((unsigned char *) paddedData.mutableBytes)[self.preview.length + i] = (unsigned char) i;

            [self cryptWithMaster:paddedData iv:nil decrypt:NO];
            locator.preview = paddedData;
        }
        else
            locator.preview = self.preview;
    }

    NSMutableData *locData = [locator save];
    [self outputData:locData.bytes ofSize:locData.length - 8];
    [self outputData:locData.bytes + locData.length - 8 ofSize:8];

    close(_archiveFileFd);
    _archiveFileFd = -1;

    // Reporting that operation was finished

    if (self.delegate && [self.delegate respondsToSelector:@selector(encryptedArchive:finishedOperation:)])
        [self.delegate encryptedArchive:self finishedOperation:@{kEncryptedArchiveOperation : kEncryptedArchiveOperationSaving}];
}

- (ENEncryptedArchiveItem *)addItem:(NSString *)aPath fromRoot:(NSString *)rootPath {
    if (!rootPath || [rootPath isEqualToString:@"/"] || [rootPath isEqualToString:aPath])
        rootPath = [aPath stringByDeletingLastPathComponent];

    if (![[aPath lowercaseString] hasPrefix:[rootPath lowercaseString]])
        return nil;

    ENEncryptedArchiveItem *newItem = [ENEncryptedArchiveItem itemFromPath:aPath error:nil];
    if (newItem) {
        if ([rootPath isEqualToString:@"/"])
            newItem.path = aPath;
        else
            newItem.path = [aPath substringFromIndex:rootPath.length];

        if ([newItem.attributes.fileType isEqualTo:NSFileTypeRegular])
            newItem.compressed = self.compressFiles;
        else
            newItem.compressed = NO;

        [self addToDirectory:newItem];
    }

    return newItem;
}

- (NSArray *)addItems:(NSArray *)pathes fromRoot:(NSString *)rootPath {
    NSMutableArray *res = [NSMutableArray new];

    for (NSString *aPath in pathes) {
        ENEncryptedArchiveItem *newItem = [self addItem:aPath fromRoot:rootPath];
        if (newItem)
            [res addObject:newItem];
    }

    return res;
}

- (void)extractItem:(ENEncryptedArchiveItem *)anItem toPath:(NSString *)aPath {
#warning Implement single item extraction
}

- (void)extractItems:(NSArray *)items toPath:(NSString *)aPath {
#warning Implement multiple items extraction code
}

@end

@implementation ENEncryptedArchiveItem

- (id)init {
    if (self = [super init]) {
        self.path = @"";
        self.realPath = @"";
        self.attributes = [NSMutableDictionary new];
        self.extendedAttributes = [NSMutableDictionary new];
        self.extendedSecurityOptions = [NSData new];
        self.UTI = @"";
        self.size = 0;
        self.localHeaderPosition = 0;
        self.fileDataPosition = 0;
        self.compressed = NO;
        self.compressedSize = 0;
        self.hmac = nil;
    }

    return self;
}

+ (ENEncryptedArchiveItem *)itemFromPath:(NSString *)aPath error:(NSError **)anError {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:aPath error:anError];
    if (!attrs)
        return nil;

    NSString *fType = [attrs fileType];
    if (!([fType isEqualToString:NSFileTypeRegular] || [fType isEqualToString:NSFileTypeDirectory] || [fType isEqualToString:NSFileTypeSymbolicLink]))
        return nil;

    ENEncryptedArchiveItem *newItem = [ENEncryptedArchiveItem new];
    newItem.realPath = aPath;
    newItem.path = aPath;

    CFStringRef UTI = nil;

    if ([fType isEqualToString:NSFileTypeDirectory]) {
        UTI = kUTTypeDirectory;
    }
    else {
        UTI = UTTypeCreatePreferredIdentifierForTag(kUTTagClassFilenameExtension, (__bridge CFStringRef) aPath.pathExtension, NULL);
    }
    newItem.UTI = (__bridge NSString *) UTI ?: aPath.pathExtension;

    if ([fType isEqualToString:NSFileTypeSymbolicLink]) {
        newItem.linkDestination = [[NSFileManager defaultManager] destinationOfSymbolicLinkAtPath:aPath error:nil];
        if (!newItem.linkDestination)
            return nil;
        newItem.size = 0;
        [newItem.attributes setObject:NSFileTypeSymbolicLink forKey:NSFileType];
    }
    else {
        [newItem.attributes addEntriesFromDictionary:attrs];

        NSDictionary *exAttrs = [ENFileMetadata extendedAttributesOfFile:aPath];
        if (exAttrs != nil) {
            [newItem.extendedAttributes addEntriesFromDictionary:exAttrs];
        }
        NSData *secOptions = [ENFileMetadata extendedSecurityOptionsOfFile:aPath];
        if (secOptions)
            newItem.extendedSecurityOptions = secOptions;

        newItem.size = [attrs fileSize];
    }

    return newItem;
}

@end

@implementation ENEncryptedArchiveDirectoryLocator

- (NSMutableData *)save {
    NSMutableData *locData = [NSMutableData new];
    [locData appendBytes:&ENHeaderLocator length:4];
    [locData appendBytes:&ENHeaderElementDirLocatorVer length:4];
    [locData appendBytes:&_version length:4];
    [locData appendBytes:&ENHeaderElementDirLocator length:4];
    [locData appendBytes:&_directoryPosition length:8];
    [locData appendBytes:&_directorySize length:8];
    [locData appendBytes:&_reserved1 length:8];
    [locData appendBytes:&_reserved2 length:8];
    [locData appendBytes:&ENHeaderElementDirFlags length:4];
    [locData appendBytes:&_flags length:4];

    if (self.hmac && (self.hmac.length == ENCR_HMAC_LEN)) {
        [locData appendBytes:&ENHeaderElementDirHMAC length:4];
        [locData appendBytes:self.hmac.bytes length:ENCR_HMAC_LEN];
    }

    if (self.salt && (self.salt.length == ENCR_SALT_LENGTH)) {
        [locData appendBytes:&ENHeaderElementMasterSalt length:4];
        [locData appendBytes:self.salt.bytes length:ENCR_SALT_LENGTH];
    }

    if (self.preview && (self.preview.length > 0)) {
        [locData appendBytes:&ENHeaderElementArchivePreview length:4];
        UInt32 len = (UInt32) self.preview.length;
        [locData appendBytes:&len length:4];
        [locData appendBytes:self.preview.bytes length:self.preview.length];
    }

    if (!self.passwordHint)
        self.passwordHint = @"";
    NSData *str = [self.passwordHint dataUsingEncoding:NSUTF8StringEncoding];
    UInt16 len;
    if (str.length > 0xffff) {
        str = [NSData dataWithBytes:(void *) str.bytes length:0xffff];
        len = 0xffff;
    }
    else
        len = (UInt16) str.length;
    [locData appendBytes:&ENHeaderElementPasswordHint length:4];
    [locData appendBytes:&len length:2];
    [locData appendBytes:str.bytes length:len];

    [locData appendBytes:&ENHeaderElementDirLocatorSize length:4];
    UInt32 lSz = (UInt32) locData.length + 4;
    [locData appendBytes:&lSz length:4];

    return locData;
}

- (BOOL)load:(NSData *)aData {
    NSUInteger index = 0, size = aData.length;

    /* header identifier */
    if ((size < 4) || (*((UInt32 *) aData.bytes) != ENHeaderLocator))
        return NO;
    size -= 4;
    index += 4;

    /* directory locator version */
    if ((size < 8) || (*((UInt32 *) (aData.bytes + index)) != ENHeaderElementDirLocatorVer))
        return NO;
    _version = *((UInt32 *) (aData.bytes + index + 4));
    size -= 8;
    index += 8;

    /* directory location : position, size and two reserved fields */
    if ((size < 36) || (*((UInt32 *) (aData.bytes + index)) != ENHeaderElementDirLocator))
        return NO;
    _directoryPosition = *((UInt64 *) (aData.bytes + index + 4));
    _directorySize = *((UInt64 *) (aData.bytes + index + 12));
    _reserved1 = *((UInt64 *) (aData.bytes + index + 20));
    _reserved2 = *((UInt64 *) (aData.bytes + index + 28));
    size -= 36;
    index += 36;

    /* directory flags */
    if ((size < 8) || (*((UInt32 *) (aData.bytes + index)) != ENHeaderElementDirFlags))
        return NO;
    _flags = *((UInt32 *) (aData.bytes + index + 4));
    size -= 8;
    index += 8;

    /* directory hmac */
    if (self.flags & (ENFlagHmacDirectory)) {
        if ((size < 4 + ENCR_HMAC_LEN) || (*((UInt32 *) (aData.bytes + index)) != ENHeaderElementDirHMAC))
            return NO;

        self.hmac = [NSMutableData dataWithBytes:aData.bytes + index + 4 length:ENCR_HMAC_LEN];
        size -= 4 + ENCR_HMAC_LEN;
        index += 4 + ENCR_HMAC_LEN;
    }

    /* master key salt */
    if (self.flags & (ENFlagEncryptFiles | ENFlagEncryptDirectory)) {
        if ((size < 4 + ENCR_SALT_LENGTH) || (*((UInt32 *) (aData.bytes + index)) != ENHeaderElementMasterSalt))
            return NO;
        self.salt = [NSMutableData dataWithBytes:aData.bytes + index + 4 length:ENCR_SALT_LENGTH];
        size -= 4 + ENCR_SALT_LENGTH;
        index += 4 + ENCR_SALT_LENGTH;
    }

    /* archive preview image, if present */
    if ((size >= 8) && (*((UInt32 *) (aData.bytes + index)) == ENHeaderElementArchivePreview)) {
        UInt32 len = *((UInt32 *) (aData.bytes + index + 4));
        if (size < len + 8)
            return NO;
        NSData *preview = [NSData dataWithBytes:aData.bytes + index + 8 length:len];
        self.preview = preview;
        size -= len + 8;
        index += len + 8;
    }

    /* password hint */
    if ((size < 6) || (*((UInt32 *) (aData.bytes + index)) != ENHeaderElementPasswordHint))
        return NO;
    UInt16 len = *((UInt16 *) (aData.bytes + index + 4));

    if (size < len + 6)
        return NO;

    NSString *hint;

    if (len > 0) {
        hint = [[NSString alloc] initWithBytes:aData.bytes + index + 6 length:len encoding:NSUTF8StringEncoding];
        if (!hint)
            return NO;
        self.passwordHint = hint;
    }
    else
        self.passwordHint = @"";

    size -= 6 + len;
    index += 6 + len;

    /* ignoring all further data */
    return YES;
}

@end