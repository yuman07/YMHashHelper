//
//  YMHashHelper.h
//  YMHashHelper
//
//  Created by yuman01 on 2018/9/13.
//  Copyright © 2018年 yuman. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 计算字符串/data/文件的hash值
 如果计算hash失败，则返回nil
 返回的hash字符串均是小写字母
 类方法：用于一次性计算hash值
 成员方法：用于流式计算hash值
 */
@interface YMHashHelper : NSObject

/// 对字符串进行hash
+ (NSString *)md5WithString:(NSString *)string;
+ (NSString *)sha1WithString:(NSString *)string;
+ (NSString *)sha256WithString:(NSString *)string;
+ (NSString *)sha512WithString:(NSString *)string;

/// 对data进行hash
+ (NSString *)md5WithData:(NSData *)data;
+ (NSString *)sha1WithData:(NSData *)data;
+ (NSString *)sha256WithData:(NSData *)data;
+ (NSString *)sha512WithData:(NSData *)data;

/// 对文件进行hash
+ (NSString *)md5WithFilePath:(NSString *)filePath;
+ (NSString *)sha1WithFilePath:(NSString *)filePath;
+ (NSString *)sha256WithFilePath:(NSString *)filePath;
+ (NSString *)sha512WithFilePath:(NSString *)filePath;

/// 成员方法：流式计算data的hash值，每次以新的data作为入参
- (void)md5UpdateWithData:(NSData *)data;
- (void)sha1UpdateWithData:(NSData *)data;
- (void)sha256UpdateWithData:(NSData *)data;
- (void)sha512UpdateWithData:(NSData *)data;

/// data传完后，调用此方法获得hash字符串
/// 注意调用完此方法后，此helper再调用update方法将无效
- (NSString *)hashTaskComplete;

@end
