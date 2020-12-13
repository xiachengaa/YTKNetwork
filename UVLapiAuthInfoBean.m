//
//  UVLapiAuthInfoBeanBean.m
//  EZViewer
//
//  Created by xiacheng on 2020/1/10.
//  Copyright © 2020 uniview. All rights reserved.
//

#import "UVLapiAuthInfoBean.h"
#import "MJExtension.h"

NSString *const UVLapiRequestAuthTypeStrBasic = @"Basic";
NSString *const UVLapiRequestAuthTypeStrDigest = @"Digest";

NSString *const UVLapiRequestHeaderWwwAuthenticateKey = @"Www-Authenticate";
NSString *const UVLapiRequestHeaderAuthorisedTypeKey = @"authorisedType";

@interface UVLapiAuthInfoBean ()

@property (copy, nonatomic, readwrite) NSString *realm;

@property (copy, nonatomic, readwrite) NSString *nonce;

@property (copy, nonatomic, readwrite) NSString *algorithm;

@property (copy, nonatomic, readwrite) NSString *qop;

@property (assign, nonatomic, readwrite) NSInteger nc;

@end

@implementation UVLapiAuthInfoBean

#pragma mark- Life Cycle
#pragma mark- Public Method
+ (instancetype)authInfoWithResoponseAllHeaderFields:(NSDictionary *)allHeaderFields
{
    NSString *authenticate = allHeaderFields[UVLapiRequestHeaderWwwAuthenticateKey];
    if (!authenticate) {
        return nil;
    }
    return [self analysisAuthenticateInfo:authenticate];
}

- (NSString *)digestAuthenticationForRequest:(YTKBaseRequest *)request
{
    NSArray<NSString *> *authorizationHeaderFieldArray = [request requestAuthorizationHeaderFieldArray];
    if (authorizationHeaderFieldArray != nil) {
        UVLapiAuthInfoBean *authInfo = _autoInfoRecord[[self finialHostForRequest:request]];
        return [self authStringWithUri:request.requestUrl userName:authorizationHeaderFieldArray.firstObject password:authorizationHeaderFieldArray.lastObject method:[self requestMethodStrForRequestMethodType:request.requestMethod]];
    }
}


- (NSString *)authStringWithUri:(NSString *)uriStr userName:(NSString *)userName password:(NSString *)password method:(NSString *)method
{
    NSString *ncStr = [self getLAPICommunictaCountsStringWithNc:self.nc];
    NSString *HA1 = [NSString md5String32:[NSString stringWithFormat:@"%@:%@:%@",userName, self.realm, password]];
    NSString *HA2 = [NSString md5String32:[NSString stringWithFormat:@"%@:%@", method, uriStr]];
    NSString *cnonce = [self randomCreatStringWithCharacterNumber:32];
    NSString *response = @"";
    if (NULL == self.qop) {
        response = [NSString md5String32:[NSString stringWithFormat:@"%@:%@:%@",HA1, self.nonce, HA2]];
    } else {
        response = [NSString md5String32:[NSString stringWithFormat:@"%@:%@:%@:%@:%@:%@", HA1, self.nonce, ncStr, cnonce, self.qop, HA2]];
    }
    NSString *authorisedString = [NSString stringWithFormat:@"Digest username=\"%@\", realm=\"%@\", qop=\"%@\", algorithm=\"MD5\", uri=\"%@\", nonce=\"%@\", nc=%@, cnonce=\"%@\", response=\"%@\"", userName, self.realm, self.qop, uriStr, self.nonce, ncStr, cnonce, response];
    return authorisedString;
}

#pragma mark- Delegate
#pragma mark- Event Response
#pragma mark- Getters and Setters
- (NSInteger)nc
{
    return 1;
}

#pragma mark- Private Method
+ (UVLapiAuthInfoBean *)analysisAuthenticateInfo:(NSString *)authenticate {
    if (!authenticate) {
        return nil;
    }
    UVLapiAuthInfoBean *authInfo = nil;
    NSMutableDictionary *authorArgumentsDic = [NSMutableDictionary dictionaryWithCapacity:0];
    if ([authenticate containsString:UVLapiRequestAuthTypeStrDigest]) {
        //Digest 鉴权
        [authorArgumentsDic setObject:UVLapiRequestAuthTypeStrDigest forKey:UVLapiRequestHeaderAuthorisedTypeKey];
        //处理Digest字符串 分离所有的参数项 example : Digest realm = "xxx",nonce = "xxx" ;
        NSMutableString *mutableAuthenticate = [NSMutableString stringWithString:authenticate];
        //1.删除开头的 'Digest' 、 '\' 和 '"' 。
        [mutableAuthenticate deleteCharactersInRange:NSMakeRange(0, 7)];
        NSMutableString *trimmedString =[NSMutableString stringWithString:[mutableAuthenticate stringByReplacingOccurrencesOfString:@"\\" withString:@""]];
        trimmedString = [NSMutableString stringWithString:[trimmedString stringByReplacingOccurrencesOfString:@"\"" withString:@""]];
        trimmedString = [NSMutableString stringWithString:[trimmedString stringByReplacingOccurrencesOfString:@" " withString:@""]];
        
        NSString *tempStr = @"";
        BOOL flag = YES;
        while (flag) {
            //2.以','为分割点 取出键值对
            NSRange range = [trimmedString rangeOfString:@","];
            if (range.location == NSNotFound) {
                //最后一组
                tempStr = trimmedString;
                flag = NO;
            } else {
                tempStr = [trimmedString substringToIndex:range.location];
                [trimmedString deleteCharactersInRange:NSMakeRange(0, range.location+1)];
            }
            //3.以'='为分割点 取出键和值 存入字典
            NSArray *array = [tempStr componentsSeparatedByString:@"="];
            NSString *key = [array firstObject];
            NSString *value = [array lastObject];
            [authorArgumentsDic setObject:value forKey:key];
        }
        authInfo = [UVLapiAuthInfoBean mj_objectWithKeyValues:authorArgumentsDic];
        authInfo.authType = UVLapiRequestAuthTypeDigest;
    } else if ([authenticate containsString:UVLapiRequestAuthTypeStrBasic]){
        authInfo = [[UVLapiAuthInfoBean alloc] init];
        authInfo.authType = UVLapiRequestAuthTypeBasic;
    }
    return authInfo;
}

- (NSString *)getLAPICommunictaCountsStringWithNc:(NSInteger)nc {
    NSMutableString *str = [NSMutableString stringWithFormat:@"%ld", (long)nc];
    //鉴权需要当前进行交换的次数(nc) 固定八位
    NSInteger num = (8 - str.length);
    for (int i = 0; i < num; i++) {
        [str insertString:@"0" atIndex:0];
    }
    return str;
}

//随机生成指定位数的大写字母与数字混合字符串
- (NSString *)randomCreatStringWithCharacterNumber:(NSInteger)number {
    NSString *string = [[NSString alloc]init];
    for (int i = 0; i < number; i++) {
        int number = arc4random() % 36;
        
        if (number < 10) {
            int figure = arc4random() % 10;
            NSString *tempString = [NSString stringWithFormat:@"%d", figure];
            string = [string stringByAppendingString:tempString];
        }else {
            int figure = (arc4random() % 26) + 65;
            char character = figure;
            NSString *tempString = [NSString stringWithFormat:@"%c", character];
            string = [string stringByAppendingString:tempString];
        }
    }
    return string;
}

- (NSString *)requestMethodStrForRequestMethodType:(YTKRequestMethod)requestMethod
{
    switch (requestMethod) {
        case YTKRequestMethodGET:
            return @"GET";
        case YTKRequestMethodPOST:
            return @"POST";
        case YTKRequestMethodHEAD:
            return @"HEAD";
        case YTKRequestMethodPUT:
            return @"PUT";
        case YTKRequestMethodDELETE:
            return @"DELETE";
        case YTKRequestMethodPATCH:
            return @"PATCH";
    }
}

@end
