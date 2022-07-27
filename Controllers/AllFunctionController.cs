using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Data;
using System.Data.SqlClient;
using EbiApi.Model;
using System.Text.RegularExpressions;

namespace EbiApi.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class AllFunctionController : ControllerBase
    {
        /*
        [HttpGet("GetNames")]
        public IActionResult GetNames() {
            var identity = (ClaimsIdentity)User.Identity;
            string strId = UniversalFunctions.FindIdentityInfo(identity, "CisNo");
            //UniversalFunctions.FindIdentityInfo(identity, ClaimTypes.NameIdentifier)

            return Ok(strId);
        }
        */

        [Authorize]
        [HttpPost("QueryResult")]
        public IActionResult QryResult([FromBody] object strParameters)
        {
            ApiResponse jsonResponse = new ApiResponse();
            try {
                var identity = (ClaimsIdentity)User.Identity;
                string strId = UniversalFunctions.FindIdentityInfo(identity, "UserLogin");
                string strSeed = UniversalFunctions.FindIdentityInfo(identity, "HshSeed");

                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());

                string strESigned = Request.Headers["E-Signed"].ToString();

                //hashing sha256 (strSeed+final_json_string)
                string strProcdSigned = UniversalFunctions.MsgSigned(JsonConvert.SerializeObject(jsonObj),strSeed);

                if (strESigned == strProcdSigned)
                {
                    jsonObj.Add("_SenderIdentity", strId);

                    //DataTable dt = UniversalFunctions.TableFromMSSQL(jsonObj["FnName"].ToString(), jsonObj["FnParam"].ToString(), JsonConvert.SerializeObject(jsonObj));
                    DataTable dt = UniversalFunctions.TableFromMSSQL(Request.Headers["FnName"].ToString(), Request.Headers["FnParam"].ToString(), JsonConvert.SerializeObject(jsonObj));

                    if (dt.Rows.Count <= 0)
                    {
                        jsonResponse.ErrorCode = "88";
                        jsonResponse.ErrorDescription = "No Record(s) Found!";
                        jsonResponse.ServerSource = "Data Server";
                    }
                    else
                    {
                        jsonResponse = UniversalFunctions.DatatableToJson(dt, "0", "Successful");
                    }
                }
                else {
                    jsonResponse.ErrorCode = "88";
                    jsonResponse.ErrorDescription = "E-signature error";
                    jsonResponse.ServerSource = "API Server";
                }
            }
            catch (Exception ex) {
                // write to textfile
                JsonLog jsnRet = UniversalFunctions.WriteLog(ex.Message);

                string strErrorDesc = " Error Encountered with ticket# -> " + jsnRet.TraceNo;

                jsonResponse.ErrorCode = "99";
                jsonResponse.ErrorDescription = strErrorDesc;
                jsonResponse.ServerSource = "Data Server";
            }
            

            //return Ok(JsonConvert.SerializeObject(jsonObj));
            return Ok(jsonResponse);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("QueryError")]
        public IActionResult QryError([FromBody] object strParameters)
        {
            ApiResponse jsonResponse = new ApiResponse();
            try {
                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());

                jsonResponse = UniversalFunctions.FindMatchInFile(jsonObj["YYYYMMDD"].ToString(), jsonObj["TicketNo"].ToString());
            }
            catch (Exception ex) {
                jsonResponse.ErrorCode = "99";
                jsonResponse.ErrorDescription = ex.Message;
                jsonResponse.ServerSource = "API Server";
            }

            return Ok(jsonResponse);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("SignedHash")]
        public IActionResult SignedHash([FromBody] object strParameters) // callable only in Development Environment
        {
            ApiResponse jsonResponse = new ApiResponse();
            try
            {
                
                var identity = (ClaimsIdentity)User.Identity;
                string strSeed = UniversalFunctions.FindIdentityInfo(identity, "HshSeed");

                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());
                string strESigned = Request.Headers["E-Signed"].ToString();

                //hashing sha256 (strSeed+final_json_string)
                string strProcdSigned = UniversalFunctions.MsgSigned(JsonConvert.SerializeObject(jsonObj), strSeed);

                jsonResponse.ErrorCode = "0";
                jsonResponse.ErrorDescription = strProcdSigned;
                jsonResponse.ServerSource = "API Server";

                
            }
            catch (Exception ex)
            {
                // write to textfile
                JsonLog jsnRet = UniversalFunctions.WriteLog(ex.Message);

                string strErrorDesc = " Error Encountered with ticket# -> " + jsnRet.TraceNo;

                jsonResponse.ErrorCode = "99";
                jsonResponse.ErrorDescription = strErrorDesc;
                jsonResponse.ServerSource = "Data Server";
            }


            //return Ok(JsonConvert.SerializeObject(jsonObj));
            return Ok(jsonResponse);
        }

    }
}
