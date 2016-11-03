using System;
using System.Data.SqlTypes;
using System.Data.SqlClient;
using Microsoft.SqlServer.Server;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Text;
using System.Security.Cryptography;
using System.Numerics;
using System.Collections.Generic;

/*На sql делаем:
 * подключаем сборку
CREATE/alter ASSEMBLY sqlDeflate from 'C:\Users\etyurin\Documents\Visual Studio 2013\Projects\sqlDll\sqlDll\bin\Release\sqlDll.dll' WITH PERMISSION_SET = SAFE
 * делаем ссылки на функции  
CREATE FUNCTION fdecode(@inbyte varbinary(max))                                                        RETURNS varbinary(max) WITH EXECUTE AS CALLER AS  EXTERNAL NAME sqlDeflate.[sqlDllmy.sqlDll].decode
CREATE FUNCTION fcode(@inbyte varbinary(max))                                                          RETURNS varbinary(max) WITH EXECUTE AS CALLER AS  EXTERNAL NAME sqlDeflate.[sqlDllmy.sqlDll].code
CREATE FUNCTION fdecodeToStr(@inbyte varbinary(max))                                                   RETURNS nvarchar(max)  WITH EXECUTE AS CALLER AS  EXTERNAL NAME sqlDeflate.[sqlDllmy.sqlDll].decodeToStr
CREATE FUNCTION fdecodeUser(@inbyte varbinary(max),@cmd nvarchar(max),@sqlPathToTable nvarchar(max))   RETURNS nvarchar(max)  WITH EXECUTE AS CALLER AS  EXTERNAL NAME sqlDeflate.[sqlDllmy.sqlDll].decodeUser
CREATE PROCEDURE load(@Path nvarchar(max))                                                                                    WITH EXECUTE AS CALLER AS  EXTERNAL NAME sqlDeflate.[sqlDllmy.sqlDll].load
 * разрешаем запускать библиотеку на шарпе
sp_configure 'show advanced options', 1;
GO
RECONFIGURE;
GO
sp_configure 'clr enabled', 1;
GO
RECONFIGURE;
GO
 * вариант использования
 select dbo.fdecodeUser(t.Data,2), * from [AS-MSK-N0255\NTVR].NTVR.dbo.v8users as t
  
declare @var nvarchar(max);
select @var=dbo.fdecodeToStr(t.BinaryData) from [AS-MSK-N0255\NTVR].NTVR.dbo.Params as t where t.FileName='DBNames';
--печатаем этот хлам
DECLARE @Counter INT
SET @Counter = 0
DECLARE @TotalPrints INT
SET @TotalPrints = (LEN(@var) / 4000) + 1
WHILE @Counter < @TotalPrints 
BEGIN
    PRINT SUBSTRING(@var, @Counter * 4000, 4000)
    SET @Counter = @Counter + 1
END
 */
namespace sqlDllmy{
    public class sqlDll {
        //Поля
        //Раскрытые хеши
        static readonly Dictionary<string, string> dd = new Dictionary<string, string>();
        //Имена ролей
        static readonly Dictionary<string, string> dicRoles = new Dictionary<string, string>();
        //Варианты наборов
        static readonly string strCharToPwd_All = @"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZабвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ.,*/-+!?@#$%()<>=~";
        static readonly string strCharToPwd_en  = @"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.,*/-+!?@#$%()<>=~";
        static readonly string strCharToPwd_ru  = @"0123456789абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ.,*/-+!?@#$%()<>=~";

        //Методы
        static string decomp(byte[] ab) { //Декодирует массив байтов
            string strResult;
            using(MemoryStream ms = new MemoryStream()) {
                ms.Write(ab, 0, ab.Length);
                ms.Seek(0, 0);
                using(DeflateStream decompressionStream = new System.IO.Compression.DeflateStream(ms, CompressionMode.Decompress)) {
                    using(StreamReader sr = new StreamReader(decompressionStream)) {
                        strResult = sr.ReadToEnd();
                    }
                }
            }
            return strResult;
        }
        [SqlFunction()]
        public static void load(string strSqlPath) {
            using(SqlConnection con = new SqlConnection("context connection=true")) {
                SqlCommand cmd = con.CreateCommand();
                cmd.CommandText = "select top 1 t.BinaryData from " + strSqlPath + " as t where t.FileName ='1a621f0f-5568-4183-bd9f-f6ef670e7090.si'";
                con.Open();
                dicRoles.Add(strSqlPath, decomp((byte[])cmd.ExecuteScalar())); ;                               
                SqlContext.Pipe.ExecuteAndSend(cmd);
            }            
        }
        [SqlFunction()]
        public static SqlBytes decode(SqlBytes sqlBB) {
            try {
                using(DeflateStream deflstrm = new DeflateStream(sqlBB.Stream, CompressionMode.Decompress)) {
                    return new SqlBytes(deflstrm);
                }
            } catch(Exception) {
                return sqlBB;
            }

        }
        [SqlFunction()]
        public static SqlBytes code(SqlBytes sqlBB) {
            try {
                using(DeflateStream deflstrm = new DeflateStream(sqlBB.Stream, CompressionMode.Compress)) {
                    return new SqlBytes(deflstrm);
                }
            } catch(Exception) {
                return sqlBB;
            }
        }
        [SqlFunction()]
        public static SqlString decodeToStr(SqlBytes sqlBB) {
            try {
                using(DeflateStream deflstrm = new DeflateStream(sqlBB.Stream, CompressionMode.Decompress)) {
                    using(StreamReader red = new StreamReader(deflstrm)) {
                        return red.ReadToEnd();
                    }
                }
            } catch(Exception ex) {
                return ex.Message;
            }            
        }
        [SqlFunction()]
        public static SqlString decodeUser(SqlBytes sqlBB, string strCmd = null,string strSqlPath = null) {
            try {
                Byte[] data;
                byte[] buffer = new byte[sqlBB.Stream.Length];
                using(MemoryStream ms = new MemoryStream()) {
                    int read;
                    while((read = sqlBB.Stream.Read(buffer, 0, buffer.Length)) > 0) 
                        ms.Write(buffer, 0, read);
                
                    data = ms.ToArray();
                }
            
                int iPoz = data[0], l = data.Length;
                byte[] Data_ = new byte[iPoz + 1];
                byte[] newData = new byte[l - iPoz - 1];
                for(int i = iPoz + 1, j = 1; i < l; i++, j = (++j) > iPoz ? 1 : j)
                    newData[i - iPoz - 1] = (byte)(data[i] ^ data[j]);

                string strdec = System.Text.Encoding.UTF8.GetString(newData);

                strCmd = strCmd.Trim().ToLower();
                Match m = Regex.Match(strCmd, @"\b(\w+)\b(\s+(\w+)\b(\s+(\d+))?)?");
                
                if(!m.Success)
                    return strdec;
                else {
                    string strCmd_1 = m.Groups[1].Value;
                    string strCmd_2 = m.Groups[3].Value;
                    int iLen=6;
                    if(!int.TryParse(m.Groups[5].Value, out iLen))
                        iLen = 6;                  

                    if(strCmd_1 == "decode") 
                        return strdec;
                    else if(strCmd_1 == "roles") {
                        m = Regex.Match(strdec, @".+?\r\n{\d+((,\w{8}-\w{4}-\w{4}-\w{4}-\w{12})*)},", RegexOptions.IgnoreCase);
                        if(m.Success) {
                            if(strCmd_2 != "id" && !dicRoles.ContainsKey(strSqlPath))
                                return "Требуется инициализация exec Load 'полный путь к таблице с учетом базы'";

                            MatchCollection mm = Regex.Matches(m.Groups[1].Value, @"\w{8}-\w{4}-\w{4}-\w{4}-\w{12}", RegexOptions.IgnoreCase);
                            StringBuilder sbRoles = new StringBuilder();
                            foreach(Match mr in mm) {
                                if(strCmd_2 == "id")
                                    sbRoles.AppendFormat("{0}\n", mr.Value);
                                else {
                                    Match mn = Regex.Match(dicRoles[strSqlPath], string.Format(@",{0},\w{{8}}-\w{{4}}-\w{{4}}-\w{{4}}-\w{{12}},\d+,""(.+?)""", mr.Value));
                                    if(mn.Success)
                                        sbRoles.AppendFormat("{0}\n", mn.Groups[1].Value);
                                    else
                                        sbRoles.AppendFormat("{0}\n", mr.Value);
                                }
                            }
                            return sbRoles.ToString();                            
                        } else
                            return "";
                    } else {
                        string hpwd = "";
                        m = Regex.Match(strdec, @"{.+},.+?""(.+?)"",""\1""");
                        if(m.Success)
                            hpwd = m.Groups[1].Value;
                        else
                            return "";

                        //Пусто пароль
                        if(dd.ContainsKey("2jmj7l5rSw0yVb/vlWAYkK/YBwk="))
                            dd.Add("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", "<не задан>");

                        if(strCmd_1 == "hpwd")
                            return hpwd;
                        else if(strCmd_1 == "pwd") {
                            if(dd.ContainsKey(hpwd))
                                return dd[hpwd];

                            string strCharToPwd;
                            if(strCmd_2 == "en")
                                strCharToPwd = strCharToPwd_en;
                            else if(strCmd_2 == "ru")
                                strCharToPwd = strCharToPwd_ru;
                            else
                                strCharToPwd = strCharToPwd_All;

                            using(SHA1 sha = new SHA1CryptoServiceProvider()) {
                                StringBuilder sb = new StringBuilder();
                                for(int i = 1; i <= iLen; i++) {                                    
                                    string pwd = getPwd(i, sha, hpwd, sb, strCharToPwd);
                                    if(pwd != string.Empty) {
                                        dd.Add(hpwd, sb.ToString());
                                        return pwd;
                                    }
                                }
                            }
                        }
                        return "";
                    }
                }
            } catch(Exception ex) {
                return ex.Message;
            }
        }       

        static string getPwd(int i, SHA1 sha, string hpwd, StringBuilder sb, string strCharToPwd) {  
            foreach(char c in strCharToPwd) {
                sb.Append(c);
                if(i - 1 > 0) {
                    if(getPwd(i - 1, sha, hpwd, sb, strCharToPwd) != string.Empty)
                        return sb.ToString();
                    else
                        sb.Remove(sb.Length - 1, 1);
                } else {
                    byte[] bHash = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                    if(hpwd == Convert.ToBase64String(bHash)) {
                        return sb.ToString();
                    } else {
                        sb.Remove(sb.Length - 1, 1);
                    }
                }
            }
            return string.Empty;
        }
    }
}

