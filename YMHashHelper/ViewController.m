//
//  ViewController.m
//  YMHashHelper
//
//  Created by yuman01 on 2018/9/13.
//  Copyright © 2018年 yuman. All rights reserved.
//

#import "ViewController.h"
#import "YMHashHelper/YMHashHelper.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSString *md5    = [YMHashHelper md5WithString:@"你好test123"];
    NSString *sha1   = [YMHashHelper sha1WithString:@"你好test123"];
    NSString *sha256 = [YMHashHelper sha256WithString:@"你好test123"];
    NSString *sha512 = [YMHashHelper sha512WithString:@"你好test123"];
    
    NSLog(@"%@\n%@\n%@\n%@", md5, sha1, sha256, sha512);
    
    YMHashHelper *helper = [[YMHashHelper alloc] init];
    [helper sha256UpdateWithData:[@"你好" dataUsingEncoding:NSUTF8StringEncoding]];
    [helper sha256UpdateWithData:[@"test123" dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *hash = [helper hashTaskComplete];
    NSLog(@"%@", hash);
    
}


@end
