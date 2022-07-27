using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using EbiApi.Model;
using System.Data;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace EbiApi
{
    public class JwtTokenManager : IJwtTokenManager
    {
        private readonly IConfiguration _configuration;
        public JwtTokenManager(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public ApiResponse Authenticate(UserCredential credential)
        {
            // include the Connection String
            // string strConnection = _configuration.GetValue<string>("ConnectionStrings:MainSql");
            // password must be hashed already with dbo.udf_hashvalue(loginId +[Password] + @vSeed) with sha256

            ApiResponse apiResp = new ApiResponse();
            string strApiDate = DateTime.Now.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'FFFzzz"); // 2021-11-22T11:29:29.4966084+08:00

            //credential.Password = UniversalFunctions.ComputeSha256Hash(credential.Password);
            //credential.Password = UniversalFunctions.ComputeSha256Hash("SampleUserpassword");

            string strCredentials = JsonConvert.SerializeObject(credential);
            try
            {
                DataTable dtCredentials = UniversalFunctions.TableFromMSSQL("UserLogin", "UserCredentials", strCredentials);

                if (dtCredentials.Rows.Count <= 0)
                //return null;
                {
                    apiResp.ErrorCode = "999";
                    apiResp.ErrorDescription = "Error";
                    apiResp.ServerSource = "Data Server";
                }
                else
                {
                    var key = _configuration.GetValue<string>("JwtConfig:Key");
                    var keyBytes = Encoding.ASCII.GetBytes(key);

                    var tokenhandler = new JwtSecurityTokenHandler();
                    var tokenDescriptor = new SecurityTokenDescriptor()
                    {
                        Subject = new ClaimsIdentity(new Claim[] {
                            new Claim(ClaimTypes.NameIdentifier, dtCredentials.Rows[0]["UserName"].ToString()),
                            new Claim("UserLogin", credential.LoginId),
                            new Claim("HshSeed", dtCredentials.Rows[0]["UserSeed"].ToString()),
                            new Claim(ClaimTypes.Role,dtCredentials.Rows[0]["ApiAccess"].ToString()),
                         }),

                        Expires = DateTime.UtcNow.AddMinutes(30),
                        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256Signature)
                    };

                    var token = tokenhandler.CreateToken(tokenDescriptor);

                    //return tokenhandler.WriteToken(token);
                    string strStatusCode = dtCredentials.Rows[0]["StatusCode"].ToString();
                    JObject varRet = new JObject{
                        { "@statusCode", strStatusCode},
                        { "@statusDesc", dtCredentials.Rows[0]["StatusDesc"].ToString()},
                        { "@serverdate", strApiDate},
                        { "@token", (strStatusCode=="0"? "": tokenhandler.WriteToken(token))}
                    };  

                    apiResp.ErrorCode = "0";
                    apiResp.ErrorDescription = "Succesful";
                    apiResp.ServerSource = "Data Server";
                    apiResp.ObjectData = varRet;
                }
            }
            catch (Exception ex) {
                JsonLog jsnRet = UniversalFunctions.WriteLog(ex.Message);
                string strErrorDesc = " Error Encountered with ticket# -> " + jsnRet.TraceNo;

                apiResp.ErrorCode = "99";
                apiResp.ErrorDescription = strErrorDesc;
                apiResp.ServerSource = "API Server";
            }

            //return JsonConvert.SerializeObject(apiResp);
            return apiResp;
    } 
    }
}
