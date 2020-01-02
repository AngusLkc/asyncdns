using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace AsyncDNSTest
{
    public enum QueryType
    {
        A = 0x01,
        AAAA = 0x1c,
        CNAME = 0x05
    }

    internal class cache
    {
        public string value;//存储数据
        public int addtime; //添加时间
        public int index;   //列表下标

        public cache(string v, int t, int i)
        {
            this.value = v;
            addtime = t;
            index = i;
        }
    }

    internal class LRUCache
    {
        private List<string> exp_list; //key_list
        private Dictionary<string, cache> dict_cache; //key=>cache(value,addtime,index)
        private int interval;
        private int last_time;

        /// <summary>
        /// 构造函数
        /// </summary>
        public LRUCache(int i)
        {
            exp_list = new List<string>();
            dict_cache = new Dictionary<string, cache>();
            last_time = Environment.TickCount;
            interval = i;
        }

        /// <summary>
        /// 更新键值
        /// </summary>
        public void put(string key, string value)
        {
            if (dict_cache.ContainsKey(key))
            {
                int index = dict_cache[key].index;
                exp_list[index] = null;
            }
            exp_list.Add(key);
            dict_cache[key] = new cache(value, Environment.TickCount, exp_list.Count - 1);
        }

        /// <summary>
        /// 获取对应值
        /// </summary>
        public string get(string key)
        {
            sweep();
            if (dict_cache.ContainsKey(key) && Environment.TickCount - dict_cache[key].addtime < 60000)
            {
                return dict_cache[key].value;
            }
            return null;
        }

        /// <summary>
        /// 清理一条缓存
        /// </summary>
        public void pop(string key)
        {
            if (dict_cache.ContainsKey(key))
            {
                exp_list[dict_cache[key].index] = null;
                dict_cache[key] = null;
                dict_cache.Remove(key);
            }
        }

        /// <summary>
        /// 清理过期缓存
        /// </summary>
        internal void sweep()
        {
            int cur_time = Environment.TickCount;
            if (cur_time - last_time > interval)
            {
                int i = 0;
                for (; i < exp_list.Count;)
                {
                    if (exp_list[i] == null)
                    {
                        i++;
                        continue;
                    }
                    else if (cur_time - dict_cache[exp_list[i]].addtime > 600000)
                    {
                        pop(exp_list[i]);
                        i++;
                        continue;
                    }
                    else if (i > 0)
                    {
                        exp_list.RemoveRange(0, i);
                        List<string> KeyList = new List<string>();
                        KeyList.AddRange(dict_cache.Keys);
                        foreach (String item in KeyList)
                        {
                            int j = dict_cache[item].index;
                            dict_cache[item].index = j - i;
                        }
                    }
                    break;
                }
                last_time = cur_time;
            }
        }
    }

    /// <summary>
    /// 回调方法定义
    /// </summary>
    public delegate void Callback(string data, int error);

    internal class AsyncDNS
    {
        private Socket socket;
        private SocketAsyncEventArgs IocpArg;
        private byte[] recvbuff;
        private IPEndPoint RemotePoint;
        private Dictionary<string, Callback> CB_Cache;
        private LRUCache DnsCache;

        /// <summary>
        /// 构造方法
        /// </summary>
        public AsyncDNS(string ServAddr)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Parse("0.0.0.0"), 0));
            socket.ReceiveBufferSize = 4096;
            socket.SendBufferSize = 4096;
            CB_Cache = new Dictionary<string, Callback>();
            DnsCache = new LRUCache(60000);
            RemotePoint = new IPEndPoint(IPAddress.Parse(ServAddr.Split(':')[0]), int.Parse(ServAddr.Split(':')[1]));
            recvbuff = new byte[4096];
            IocpArg = new SocketAsyncEventArgs();
            IocpArg.Completed += RecvCB;
            IocpArg.SetBuffer(recvbuff, 0, 4096);
            IocpArg.RemoteEndPoint = RemotePoint;
            socket.ReceiveFromAsync(IocpArg);
        }

        /// <summary>
        /// Socket Recv回调
        /// </summary>
        private void RecvCB(object sender, SocketAsyncEventArgs e)
        {
            if (e.SocketError == SocketError.Success)
            {
                int size = e.BytesTransferred;
                byte[] buffer = new byte[size];
                Array.Copy(e.Buffer, buffer, size);
                parse_response(buffer);
            }
            IocpArg.SetBuffer(recvbuff, 0, 4096);
            if (!socket.ReceiveFromAsync(IocpArg))
            {
                RecvCB(null, IocpArg);
            }
        }

        /// <summary>
        /// Socket事件循环
        /// </summary>
        public void Lookup(string hostname, QueryType qtype, Callback cb)
        {
            if (ChkIPValid(hostname))
            {   //hostname is ip
                cb(hostname, 0);
                return;
            }
            else if (!ChkNameValid(hostname))
            {   //非法域名格式
                cb(null, 1);
                return;
            }
            string key = hostname + '.' + qtype.ToString();
            string res = DnsCache.get(key);
            if (res!=null && res.Length > 1)
            {   //存在缓存
                cb(res, 0);
                return;
            }
            else if (CB_Cache.ContainsKey(key))
            {
                CB_Cache[key] += cb; //委托链
                return;
            }
            else
            {
                int datalen = 0;
                byte[] req_data = build_request(hostname, qtype, ref datalen);
                if (req_data == null || datalen < 20)
                    return;
                socket.SendTo(req_data, datalen, SocketFlags.None, RemotePoint);
                CB_Cache[key] = null;
                CB_Cache[key] += cb;
                return;
            }
        }

        /// <summary>
        /// 构造域名压缩格式
        /// </summary>
        private string build_hostname(string hostname)
        {
            string[] labels = hostname.Trim('.').Split('.');
            string result = "";
            foreach (string label in labels)
            {
                int l = label.Length;
                if (l > 63)
                    return null;
                result += (char)(l & 0xff) + label;
            }
            return result + '\0';
        }

        /// <summary>
        /// 构造问题记录
        /// </summary>
        private byte[] build_record(string hostname, QueryType qtype)
        {
            string _name = build_hostname(hostname);
            if (_name == null || _name.Length <= 4)
                return null;
            byte[] record = new byte[_name.Length + 4];
            byte[] name = Encoding.ASCII.GetBytes(_name);
            Array.Copy(name, record, name.Length);
            record[_name.Length] = 0x00;
            record[_name.Length + 1] = 0x01;
            record[_name.Length + 2] = 0x00;
            record[_name.Length + 3] = 0x01;
            return record;
        }

        /// <summary>
        /// 构造查询请求
        /// </summary>
        private byte[] build_request(string hostname, QueryType qtype,ref int len)
        {
            byte[] dns_req = new byte[1024];
            int qid = new Random().Next(65535);
            //ID
            dns_req[0] = (byte)(qid >> 8);
            dns_req[1] = (byte)(qid & 0xff);
            //标志
            dns_req[2] = 0x01;
            dns_req[3] = 0x00;
            //问题数
            dns_req[4] = 0x00;
            dns_req[5] = 0x01;
            //回答数量
            dns_req[6] = 0x00;
            dns_req[7] = 0x00;
            //授权记录数
            dns_req[8] = 0x00;
            dns_req[9] = 0x00;
            //附加记录数
            dns_req[10] = 0x00;
            dns_req[11] = 0x00;
            byte[] question = build_record(hostname, qtype);
            if (question == null || question.Length <= 8)
                return null;
            Array.Copy(question, 0, dns_req, 12, question.Length);
            len = 12 + question.Length;
            return dns_req;
        }

        /// <summary>
        /// 解析IPv4地址
        /// </summary>
        private string parse_ip(byte[] data, int offset)
        {
            if (data.Length < offset + 4)
                return null;
            int ip = data[offset] << 24 | data[offset + 1] << 16 | data[offset + 2] << 8 | data[offset + 3];
            StringBuilder sb = new StringBuilder();
            sb.Append(ip >> 0x18 & 0xff).Append(".");
            sb.Append(ip >> 0x10 & 0xff).Append(".");
            sb.Append(ip >> 0x8 & 0xff).Append(".");
            sb.Append(ip & 0xff);
            return sb.ToString();
        }

        /// <summary>
        /// 解析域名字符串
        /// </summary>
        private int parse_name(byte[] data, int offset, ref string hostname)
        {
            List<string> labels = new List<string>();
            if (data.Length <= offset)
                return 0;
            int index = offset;
            byte flag = data[index];
            while (flag > 0)
            {
                if ((flag & 0x80) > 0 && (flag & 0x40) > 0)
                {
                    int name_ptr = ((flag & 0x3f) << 8) | (data[index+1] & 0xff);
                    string label = "";
                    parse_name(data, name_ptr, ref label);
                    labels.Add(label);
                    index += 2;
                    hostname = string.Join(".", labels.ToArray<string>());
                    return index - offset;
                }
                else
                {
                    if (data.Length < index + 1 + flag)
                        return 0;
                    string label = Encoding.UTF8.GetString(data, index + 1, flag);
                    labels.Add(label);
                    index += flag + 1;
                }
                if (data.Length > index)
                    flag = data[index];
                else
                    break;
            }
            index += 1;
            hostname = string.Join(".", labels.ToArray<string>());
            return index - offset;
        }

        /// <summary>
        /// 解析回答记录,返回记录的数据
        /// </summary>
        private string parse_record(byte[] data, int offset, ref int item_len)
        {
            int name_len = 0;
            string name = "";
            name_len = parse_name(data, offset, ref name);
            if (name.Length <= 0 || name_len <= 0)
            {
                return null;
            }
            int qtype = (data[offset + name_len] & 0xff) << 8 | (data[offset + name_len + 1] & 0xff);
            string res = "";
            int res_len = 0;
            if ((QueryType)qtype == QueryType.CNAME)
            {
                res_len = parse_name(data, offset + name_len + 10, ref res);
                if (res_len <= 0 || res == null)
                {
                    return null;
                }
            }
            else if((QueryType)qtype == QueryType.A)
            {
                res_len = (data[offset + name_len + 8] & 0xff) << 8 | (data[offset + name_len + 9] & 0xff);
                res = parse_ip(data, offset + name_len + 10);
                if (res == null || res.Length <= 0)
                    return null;
            }
            else
            {
                return null;
            }
            item_len = name_len + res_len + 10;
            return res;
        }

        /// <summary>
        /// 解析问题记录,返回:www.baidu.com.A
        /// </summary>
        private string parse_queries(byte[] data, int offset, ref int q_len)
        {
            string name="";
            int name_len = parse_name(data, offset, ref name);
            if (name_len <= 0)
            {
                q_len = 0;
                return null;
            }
            QueryType qtype = (QueryType)((data[offset + name_len] & 0xff) << 8 | (data[offset + name_len + 1] & 0xff));
            name += '.' + qtype.ToString();
            q_len = name_len + 4;
            return name;
        }

        /// <summary>
        /// 校验IP地址格式
        /// </summary>
        private bool ChkIPValid(string ipaddr)
        {
            string[] gp = ipaddr.Split(new char[] { '.' });
            if (gp.Length != 4)
                return false;
            foreach (string item in gp)
            {
                int res = -1;
                try
                {
                    res = int.Parse(item);
                }
                catch
                {
                    return false;
                }
                if (res < 0 || res > 255)
                {
                    return false;
                }
            }
            try
            {
                IPAddress.Parse(ipaddr);
            }
            catch (FormatException)
            {
                return false;
            }
            catch (ArgumentException)
            {
                return false;
            }
            return true;
        }

        /// <summary>
        /// 校验域名格式
        /// </summary>
        private bool ChkNameValid(string hostname)
        {
            return Regex.IsMatch(hostname, @"^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$");
        }

        /// <summary>
        /// 解析DNS响应包
        /// </summary>
        private void parse_response(byte[] data)
        {
            int r_id = 0, r_op = 0, r_rc = 0, r_qdcount = 0, r_ancount = 0, r_nscount = 0, r_arcount = 0, offset = 12;
            bool r_qr, r_aa, r_tc, r_rd, r_ra;
            if (data.Length > 12)
            {
                r_id = ((data[0] & 0xff) << 8) | (data[1] & 0xff);  //请求ID
                r_qr = (data[2] & 128) == 128;  //查询/响应标志;0查询,1响应
                r_op = (data[2] >> 3 & 15);     //查询类型;0标准查询,1反向查询,2服务器状态
                r_aa = (data[2] & 4) == 4;      //表示授权回答
                r_tc = (data[2] & 2) == 2;      //表示可截断的
                r_rd = (data[2] & 1) == 1;      //表示期望递归
                r_ra = (data[3] & 128) == 128;  //表示可用递归
                r_rc = (data[3] & 15);          //状态码;0没有错误,1报文错误,2服务器错误,3域名差错
                r_qdcount = ((data[4] & 0xff) << 8) | (data[5] & 0xff);     //问题数
                r_ancount = ((data[6] & 0xff) << 8) | (data[7] & 0xff);     //回答数
                r_nscount = ((data[8] & 0xff) << 8) | (data[9] & 0xff);     //授权数
                r_arcount = ((data[10] & 0xff) << 8) | (data[11] & 0xff);   //附加数
            }
            else
            {
                return;
            }
            if (r_rc > 0 || !r_qr)
            {
                return;
            }
            int i;
            string hostname = "";
            //解析查询问题记录
            for (i = 0; i < r_qdcount; i++)
            {
                int len = 0;
                hostname = parse_queries(data, offset,ref len); //www.baidu.com.A
                if (len <= 0 || hostname.Length < 4 || !CB_Cache.ContainsKey(hostname))
                    return;
                offset += len;
            }
            //解析查询应答记录
            for (i = 0; i < r_ancount; i++)
            {
                int len = 0;
                string res = parse_record(data, offset, ref len);
                if (len <= 0 || res.Length <= 0)//解析出错
                    return;
                offset += len;
                if (ChkIPValid(res))
                {   //解析成功
                    DnsCache.put(hostname, res);//更新DNS解析缓存
                    CB_Cache[hostname](res,0);  //执行委托链
                    CB_Cache.Remove(hostname);
                    return;
                }
                else
                {   //解析A记录遇到CNAME别名时忽略
                    continue;
                }
            }
        }
    }
}
