# asyncdns
异步DNS解析支持For C#，目前仅支持域名A记录IPv4格式解析。

# 待修复：
如果域名解析失败,则会导致此域名的回调方法一直存在于缓存中占用内存，
改进建议:使用LRUCache缓存所有回调方法,并定时清理闲置超时的回调。

# 待改进：
1、新增IPv6、TXT、MX记录查询支持。
2、域名解析成功后需要执行的回调方法改成异步执行。

# 使用说明：
AsyncDNS adns = new AsyncDNS("223.5.5.5:53");
adns.Lookup("www.baidu.com", QueryType.A, CustomCallbackFunction);
