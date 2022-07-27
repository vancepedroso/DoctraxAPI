using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using EbiApi.Model;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Net;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;

namespace EbiApi
{
    public class UniversalFunctions
    {
        private static string strConnection = Startup.StaticConfig.GetConnectionString("MainSql");
        public static string FindIdentityInfo(ClaimsIdentity identity, string strType)
        {
            
            //return var identity = (ClaimsIdentity)User.Identity;
            string strReturn = null;
            try
            {
                var varReturn = identity.Claims
                    .Where(c => c.Type == strType)
                    .Select(c => c.Value);

                strReturn = string.Join(",", varReturn.ToList());
            }
            catch (Exception) { throw; }
            return strReturn;

        }

        public static DataTable TableFromMSSQL(string strSP, string strParameterName, string strParameterValue)
        {
            DataTable dt = new DataTable();
            using (SqlConnection conn = new SqlConnection(strConnection))
            {
                SqlCommand cmd = new SqlCommand(("sp_" + strSP), conn);

                SqlParameter param1 = new SqlParameter();
                param1.ParameterName = ("@p" + strParameterName);
                param1.SqlDbType = SqlDbType.NVarChar;
                param1.Value = strParameterValue;
                cmd.Parameters.Add(param1);
                cmd.CommandType = CommandType.StoredProcedure;

                SqlDataAdapter da = new SqlDataAdapter();
                da.SelectCommand = cmd;
                da.Fill(dt);
            }
            return dt;
        }
        public static ApiResponse DatatableToJson(DataTable table, string strErrorCode, string strErrorDesc)
        {
            ApiResponse apiResponse = new ApiResponse();
            try
            {
                var objData = JsonConvert.SerializeObject(table);
                apiResponse.ErrorCode = strErrorCode;
                apiResponse.ErrorDescription = strErrorDesc;
                apiResponse.ServerSource = "Data Server";
                apiResponse.ObjectData = objData;
            }
            catch (Exception ex) {
                apiResponse.ErrorCode = "99";
                apiResponse.ErrorDescription = "Error Conversion of DataTable";
                apiResponse.ServerSource = "API Server";
            }

            return apiResponse;
        }

        public static string ComputeSha256Hash(string rawData)
        {
            // 1. convert data to SHA256 bytes
            // 2. Convert to bytes to B64String

            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                //Convert to base64string
                return Convert.ToBase64String(bytes);

                /*
                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
                */
            }
        }

        public static JsonLog WriteLog(string strActualError) {
            
            var generator = new Random();

            string strErrorLog = DateTime.Now.ToString("yyyyMMdd");
            string strTimeOnly = DateTime.Now.ToString("HH:mm:ss ffff");
            string strRandomNo = generator.Next(100000, 999999).ToString();
            string strWriteError = strTimeOnly + " (" + strRandomNo + ") - " + strActualError;

            string path = "ErrorLogs//" + strErrorLog + ".log";
            using (StreamWriter sw = File.AppendText(path))
            {
                sw.WriteLine(strWriteError);
            }

            JsonLog jsorReturn = new JsonLog();
            jsorReturn.TraceNo = strRandomNo;
            jsorReturn.FileDate = strErrorLog;
            jsorReturn.FileDate = strTimeOnly;

            return jsorReturn;
        }

        public static  ApiResponse FindMatchInFile(string strLogfile, string strTicketNo)
        {
            ApiResponse apiResp = new ApiResponse();
            string line;
            int match;
            string readfilePath = "ErrorLogs//" + strLogfile + ".log";
            string matchstring = " (" + strTicketNo + ")";

            var lstErrors = new List<string>();

            using (StreamReader reader = new StreamReader(readfilePath))
            {
                while (reader.Peek() >= 0)
                {
                    line = reader.ReadLine();
                    match = line.IndexOf(matchstring);

                    if (match != -1)
                    {
                        lstErrors.Add(line.ToString());
                    }
                }

                reader.Close();
            }

            if (lstErrors.Count > 0)
            {
                apiResp.ErrorCode = "0";
                apiResp.ErrorDescription = "Found Match(es)";
                apiResp.ObjectData = lstErrors;
            }
            else
            {
                apiResp.ErrorCode = "88";
                apiResp.ErrorDescription = "NO Match found";
            }

            return apiResp;
        }

        public static string GetUniqueKey(int maxSize)
        {
            char[] chars = new char[62];
            chars =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
            byte[] data = new byte[1];
            RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider();
            crypto.GetNonZeroBytes(data);
            data = new byte[maxSize];
            crypto.GetNonZeroBytes(data);
            StringBuilder result = new StringBuilder(maxSize);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }

        public static string MsgSigned(string strMessage, string strSeed) {
            //Regex.Replace(strParameters.ToString(), @"[^0-9a-zA-Z:,'{}]+", "") //replace all characrter that has no match
            //Regex.Replace(strParameters.ToString(), @"\p{C}+", string.Empty) replace non printable characters

            // 1. Remove all non printable characters
            // 2. Convert msg to base64
            // 3. Concatenate HshSeed+B64Msg
            // 4. Compute cancated value to SHA256

            string strCleaned = Regex.Replace(strMessage.ToString(), @"\p{C}+", string.Empty); // replace non printable characters
            strCleaned = Convert.ToBase64String(Encoding.ASCII.GetBytes(strSeed + strCleaned));

            return ComputeSha256Hash(strCleaned);
        }

        public static Object SendApiRequest(string strTargetUri, string strMethod, string strRequestHeader, string strRequestData)
        {
            //https://long2know.com/2016/07/consuming-a-soap-service-using-httpclient/

            TimeSpan _timeout = TimeSpan.FromSeconds(10);
            Object apiResponse;

            try
            {
                using (var client = new HttpClient(new HttpClientHandler() { AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip }) { Timeout = _timeout })
                {
                    var request = new HttpRequestMessage()
                    {
                        RequestUri = new Uri(strTargetUri),
                        Method = (strMethod == "POST" ? HttpMethod.Post : HttpMethod.Get)
                    };

                    if (strRequestData != "") { // add in the BODY Information
                        request.Content = new StringContent(strRequestData, Encoding.UTF8, "application/json");
                    }


                    if (strRequestHeader != "") // Add HEADER information
                    {
                        JObject jsonHeader = (JObject)JsonConvert.DeserializeObject(strRequestHeader);

                        foreach (KeyValuePair<string, JToken> keyValuePair in jsonHeader)
                        {
                            request.Headers.Add(keyValuePair.Key.ToString(), keyValuePair.Value.ToString());
                        }
                    }

                    HttpResponseMessage response = client.SendAsync(request).Result;

                    if (!response.IsSuccessStatusCode)
                    {
                        apiResponse = new ApiResponse
                        {
                            ErrorCode = response.StatusCode.ToString(),
                            ErrorDescription = response.ReasonPhrase.ToString(),
                            ServerSource = "Endpoint API",
                            ObjectData = "Message Request -> " + response.RequestMessage.ToString(),
                        };
                    }
                    else
                    {
                        Task<Stream> streamTask = response.Content.ReadAsStreamAsync();
                        Stream stream = streamTask.Result;

                        string strContent = String.Empty;
                        using (var sr = new StreamReader(stream, Encoding.UTF8))
                        {
                            strContent = sr.ReadToEnd();
                        }

                        apiResponse = JsonConvert.DeserializeObject(strContent);
                       
                    }
                }
            }
            catch (Exception ex)
            {
                apiResponse = new ApiResponse
                {
                    ErrorCode = "9999",
                    ErrorDescription = "Error while transacting to EBI API point B",
                    ServerSource = "Front API",
                    ObjectData = ex.Message,
                };

            }

            return apiResponse;
        }

        public static object GetJwtTokenValue(string strToken, string strKey)
        {
            ApiResponse apiResp = new ApiResponse();
            try
            {
                apiResp.ErrorCode = "0";
                apiResp.ErrorDescription = "Succesful";
                apiResp.ServerSource = "API Server";

                // start reading the token
                var handler = new JwtSecurityTokenHandler();
                var jwtSecurityToken = handler.ReadJwtToken(strToken);
                var claims = jwtSecurityToken.Claims.ToList();
                //DateTime exp = jwtSecurityToken.ValidTo.ToLocalTime();

                if (jwtSecurityToken.ValidFrom <= DateTime.UtcNow && jwtSecurityToken.ValidTo >= DateTime.UtcNow)
                {
                    apiResp.ObjectData = claims.Find(item => item.Type == strKey).Value;
                }
                else
                {
                    apiResp.ErrorCode = "88";
                    apiResp.ErrorDescription = "Token not valid";
                }
            }
            catch (Exception ex)
            {
                apiResp.ErrorCode = "99";
                apiResp.ErrorDescription = ex.Message;
            }
            

            return apiResp;

        }
        


    }
}
