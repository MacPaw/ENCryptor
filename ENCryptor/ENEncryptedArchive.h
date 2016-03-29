//
//  ENEncryptedArchive.h
//  Encrypto
//
//  Created by Nickolay O. on 11/27/14.
//  Copyright (c) 2014 MacPaw. All rights reserved.
//

#import <Foundation/Foundation.h>

/* delegate operation constants */

extern NSString *const kEncryptedArchiveOperationOpening;
extern NSString *const kEncryptedArchiveOperationSaving;
extern NSString *const kEncryptedArchiveOperationExtraction;

/* delegate operation info dictionary fields */

extern NSString *const kEncryptedArchiveOperation;
extern NSString *const kEncryptedArchiveItem;
extern NSString *const kEncryptedArchiveError;
extern NSString *const kEncryptedArchiveUnderlyingError;
extern NSString *const kEncryptedArchiveItemProgress;
extern NSString *const kEncryptedArchiveTotalProgress;

/* Error messages and codes */

extern NSString *const ENEncryptedArchiveErrorDomain;
extern const int ENEncryptedArchiveErrorOperationCancelled;
extern const int ENEncryptedArchiveFileCreationFailed;
extern const int ENEncryptedArchiveFileOpeningFailed;
extern const int ENEncryptedArchiveFileReadingFailed;
extern const int ENEncryptedArchiveLocalHeaderCreationFailed;
extern const int ENEncryptedArchiveDirectoryHeaderCreationFailed;
extern const int ENEncryptedArchiveDirectoryEncryptionFailed;
extern const int ENEncryptedArchiveEncryptionFailed;
extern const int ENEncryptedArchiveOpeningFailed;
extern const int ENEncryptedArchiveMagicCheckFailed;
extern const int ENEncryptedArchiveInvalidDirectoryLocatorSize;
extern const int ENEncryptedArchiveInvalidDirectoryLocator;
extern const int ENEncryptedArchiveUnsupportedVersion;
extern const int ENEncryptedArchiveInvalidDirectoryRecord;
extern const int ENEncryptedArchiveInvalidEncryptionSettings;
extern const int ENEncryptedArchiveArchiveNotOpened;
extern const int ENEncryptedArchiveNoOutputDirectory;
extern const int ENEncryptedArchiveUnknownItemType;
extern const int ENEncryptedArchiveCannotCreateExtractionFile;
extern const int ENEncryptedArchiveCannotReadLocalHeader;
extern const int ENEncryptedArchiveInvalidLocalHeader;
extern const int ENEncryptedArchiveItemExtractionFailed;
extern const int ENEncryptedArchiveDecryptionFailed;
extern const int ENEncryptedArchiveNoPasswordSpecified;
extern const int ENEncryptedArchiveErrorDirectoryHMACMismatch;

typedef enum ENEncryptedArchiveAction : NSUInteger {
    ENActionIgnore,
    ENActionCancel
} ENEncryptedArchiveAction;

@protocol ENEncryptedArchiveDelegate;
@class ENEncryptedArchiveItem;

@interface ENEncryptedArchive : NSObject

/**
 * All file records in the archive. Populated during the loading of archive or by adding new files in archive.
 * @return An array of ENEncryptedArchiveItem objects
 */
@property (readonly) NSArray *fileRecords;
/// Encrypt files.
@property BOOL encryptFiles;
/// Encrypt files directory. If it is not encrypted everybody can see contents of archive (but still cannot decrypt the data).
@property BOOL encryptDirectory;
/// Calculate HMAC over the each file in archive
@property BOOL calculateFilesHmac;
/// Calculate HMAC over the directory
@property BOOL calculateDirectoryHmac;
/// Whether compress files or not
@property BOOL compressFiles;
/// Compression level (1..9) if compression is used
@property NSUInteger compressionLevel;
/// Password used to encrypt/decrypt the archive
@property (strong) NSString *password;
/// Password hint
@property (strong) NSString *passwordHint;
/// Archive comment - unencrypted.
@property (strong) NSString *comment;
/// Archive preview image data
@property (strong) NSData *preview;
/// Archive contains applications
@property (assign, readonly) BOOL includeApplications;
/// AES key size
@property NSUInteger AESKeyBits;
/// Delegate to handle archive operations callbacks (like progress, cancel, etc.)
@property (weak) id <ENEncryptedArchiveDelegate> delegate;

/**
 * Create new empty archive.
 * @return New empty archive with default settings.
 */
+ (ENEncryptedArchive *)archive;

/**
 * Open existing archive at the specified path and parse directory.
 * Blocking operation, so should not be called from the main thread.
 * All the progress is returned via the delegate on the same thread as method was called.
 */
- (void)openArchive:(NSString *)archivePath;

/**
 * Close previously opened archive and cleanup all data
 */
- (void)closeArchive;

/**
 * Add item to the archive. Just adds record to directory - doesn't perform any encryption or reading from file. Use method save to commit changes.
 * @param aPath path of the item which is added to archive. If it is a folder all child items are added as well.
 * @param rootPath path, from which aPath should be calculated to correctly set relative path inside of archive. Can be nil to add items to the root of archive.
 * @return Added archive item on success. Otherwise nil.
 */
- (ENEncryptedArchiveItem *)addItem:(NSString *)aPath fromRoot:(NSString *)rootPath;

/**
 * Add items to the archive. Just adds records to directory - doesn't perform any encryption or reading from file. Use method save to commit changes.
 * @param pathes array of NSString items, each is the path of the item which should be added to archive;
 * @param rootPath path, from which pathes should be calculated to correctly set relative path inside of archive. Can be nil to add items to the root of archive.
 * @return Array of added archive items. Can be empty if nothing is added. Will contain only added root items, i.e. childs of folders will not be returned.
 */
- (NSArray *)addItems:(NSArray *)pathes fromRoot:(NSString *)rootPath;
/**
 * Extract item from the archive to the specified path.
 * @param anItem Item to be extracted. If it is a directory all child items will be extracted as well.
 * @param aPath Full path of the output item (including item's name as well, so item can be renamed on extraction)
 */
//- (void) extractItem:(ENEncryptedArchiveItem*)anItem toPath:(NSString*)aPath;
/**
 * Extract items from the archive to the specified path.
 * @param items Array of the ENEncryptedArchiveItem objects. If it contains directories their child items will be extracted as well.
 * @param aPath Full path of the output directory
 */
//- (void) extractItems:(NSArray*)items toPath:(NSString*)aPath;
/**
 * Extract all items from the archive to the specified path.
 * @param aPath Full path of the output directory
 */
- (void)extractAllItems:(NSString *)aPath;

/**
 * Commit changes to archive, saving and encrypting all the items in archive corresponding to the class properties.
 * All progress is reported via the delegate methods.
 * @param outPath Path to which archive should be saved.
 */
- (void)save:(NSString *)outPath;

/**
 * Returns the record at the given relative path inside of archive.
 * @param aPath Relative path inside of archive. Cannot be nil.
 * @return ENEncryptedArchiveItem object. Can be nil if there is no item at the path.
 */
- (ENEncryptedArchiveItem *)recordAtPath:(NSString *)aPath;

/**
 * Returns the child records of the given relative path inside of archive.
 * @param aPath Relative path inside of archive. Can be nil or / for the root of archive.
 * @return Array of ENEncryptedArchiveItem objects. Can be empty if no items are found.
 */
- (NSArray *)childRecordsAtPath:(NSString *)aPath;

/**
 * Returns the child records of the specified item.
 * @param anItem Item, which child records should be returned. Must be a nil (for archive root) or directory record.
 * @return Array of ENEncryptedArchiveItem objects. Can be empty if no items are found.
 */
- (NSArray *)childRecords:(ENEncryptedArchiveItem *)anItem;

@end

@protocol ENEncryptedArchiveDelegate <NSObject>
@optional
/**
 * Called when operation like saving or file extraction is started.
 * @param info Info dictionary with single element - operation name. Can be obtained by key kEncryptedArchiveOperation
 */
- (void)encryptedArchive:(ENEncryptedArchive *)archive startedOperation:(NSDictionary *)info;

/**
 * Called to inform about the progress of operation like saving or file extraction.
 * @param info Info dictionary with the following elements:
 * - kEncryptedArchiveOperation - current operation name;
 * - kEncryptedArchiveItem - item which is currently being processed. Can be absent if no item in context.
 * - kEncryptedArchiveItemProgress - operation progress for the current item. NSNumber with float value in percents. Can be absent when there is no item in context.
 * - kEncryptedArchiveTotalProgress - overall progress, NSNumber with float value in percents.
 * @param cancel Allows to cancel the operation.
 */
- (void)encryptedArchive:(ENEncryptedArchive *)archive operationProgress:(NSDictionary *)info cancel:(BOOL *)cancel;

/**
 * Called to inform about the fatal error during the operation.
 * @param info Info dictionary with the following elements:
 * - kEncryptedArchiveOperation - current operation name;
 * - kEncryptedArchiveItem - currently processed item. Can be absent if there is no item in context.
 * - kEncryptedArchiveError - NSError within ENEncryptedArchiveErrorDomain domain.
 * - kEncryptedArchiveUnderlyingError - underlying error (like POSIX file read error) caused the problem.
 */
- (void)encryptedArchive:(ENEncryptedArchive *)archive operationError:(NSDictionary *)info;

/**
 * Called to inform that operation was successfully finished.
 * @param info Info dictionary with the following elements:
 * - kEncryptedArchiveOperation - current operation name;
 */
- (void)encryptedArchive:(ENEncryptedArchive *)archive finishedOperation:(NSDictionary *)info;

/**
 * Called to inform that there is a password required for operation (opening of the archive or file extraction).
 * Password should be assigned to .password property or cancel should be set to true if user doesn't want to specify a password.
 */
- (void)encryptedArchivePasswordNeeded:(ENEncryptedArchive *)archive cancel:(BOOL *)cancel;

/**
 * Called to inform that there is a problem with file's or directory HMAC.
 *
 */
- (void)encryptedArchive:(ENEncryptedArchive *)archive HMACMismatch:(ENEncryptedArchiveItem *)forItem action:(ENEncryptedArchiveAction *)action;

@end

@interface ENEncryptedArchiveItem : NSObject

/// Relative path of item inside of archive
@property (strong) NSString *path;
/// Path of the corresponding file in file system. Set on addition or after extraction.
@property (strong) NSString *realPath;
/// Dictionary of attributes, similar to ones returned by NSFileManager
@property (strong) NSMutableDictionary *attributes;
/// Dictionary of extended attributes, keys are extended attribute names, values are NSData elements
@property (strong) NSMutableDictionary *extendedAttributes;
/// Extended security options
@property (strong) NSData *extendedSecurityOptions;
/// Universal type identifier of the item
@property (strong) NSString *UTI;
/// Symbolic link destination
@property (strong) NSString *linkDestination;
/// File size
@property UInt64 size;
/// Position of local file header record in the archive
@property UInt64 localHeaderPosition;
/// Position of file data in the archive
@property UInt64 fileDataPosition;
/// If file is compressed
@property BOOL compressed;
/// Compressed file data size
@property UInt64 compressedSize;
/// File (+local header if it is encrypted) hmac as it is loaded from the directory
@property NSData *hmac;

@end