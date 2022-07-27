using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using EbiApi.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace EbiApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly IJwtTokenManager _tokenManager;

        public TokenController(IJwtTokenManager jwtTokenManager) {
            _tokenManager = jwtTokenManager;
        }

        [AllowAnonymous]
        [HttpPost("Authenticate")]
        public IActionResult Authenticate([FromBody] UserCredential credential) {
            ApiResponse token = _tokenManager.Authenticate(credential);

            try
            {

                //if (string.IsNullOrEmpty(token))
                if (token.ErrorCode == "999")
                    return Unauthorized();
            }
            catch (Exception ex) {
                token.ErrorCode = "99";
                token.ErrorDescription = ex.Message;
                token.ServerSource = "API Server";
            }

            return Ok(JsonConvert.SerializeObject(token));
            //return Ok(JsonConvert.DeserializeObject(JsonConvert.SerializeObject(token)));
            //return Ok(token);
        }

        [AllowAnonymous]
        [HttpPost("Start")]
        public IActionResult OpenQuery([FromBody] object strParameters) // this is for non authenticated funtions
        {
            ApiResponse jsonResponse = new ApiResponse();
            try
            {
                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());

                if (Request.Headers["FnName"].ToString() == "RegisterUser") // add another functionname which will allowed to use this function
                {
                    DataTable dt = UniversalFunctions.TableFromMSSQL(Request.Headers["FnName"].ToString(), Request.Headers["FnParam"].ToString(), JsonConvert.SerializeObject(jsonObj));
                    //DataTable dt = UniversalFunctions.TableFromMSSQL(jsonObj["FnName"].ToString(), jsonObj["FnParam"].ToString(), JsonConvert.SerializeObject(jsonObj));
                    jsonResponse = UniversalFunctions.DatatableToJson(dt, "0", "Successful");
                }
                else {
                    jsonResponse.ErrorCode = "99";
                    jsonResponse.ErrorDescription = "Restricted call";
                    jsonResponse.ServerSource = "API Server";
                }
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

        [AllowAnonymous]
        [HttpGet("ValidateUser")]
        public IActionResult ValidateUser(string UserValidate, string UserType) {
            ApiResponse jsonResponse = new ApiResponse();
            try
            {
                var jsonObject = new JObject();
                jsonObject.Add("SeedKey", UserValidate);
                jsonObject.Add("UserType", UserType);

                DataTable dt = UniversalFunctions.TableFromMSSQL("UserValidation", "SeedKey", JsonConvert.SerializeObject(jsonObject));
                jsonResponse = UniversalFunctions.DatatableToJson(dt, "0", "Successful");
            }
            catch (Exception ex) {
                JsonLog jsnRet = UniversalFunctions.WriteLog(ex.Message);

                string strErrorDesc = " Error Encountered with ticket# -> " + jsnRet.TraceNo;

                jsonResponse.ErrorCode = "99";
                jsonResponse.ErrorDescription = strErrorDesc;
                jsonResponse.ServerSource = "Data Server";
            }
            return Ok(jsonResponse);
        }

        [AllowAnonymous]
        [HttpPost("SendToApi")]
        public IActionResult SendtoAPI([FromBody] object strParameters) {
            object objResp;
            
            try
            {
                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());
                string strXHeader = (String.IsNullOrEmpty(jsonObj["Header"].ToString()) ? "" : jsonObj["Header"].ToString());
                string strXBody = (String.IsNullOrEmpty(jsonObj["Body"].ToString()) ? "" : jsonObj["Body"].ToString());

                objResp = UniversalFunctions.SendApiRequest(
                                jsonObj["ApiUrl"].ToString(),
                                jsonObj["RequestMethod"].ToString(),
                                strXHeader,strXBody);
            }
            catch (Exception ex)
            {
                ApiResponse jsonResponse = new ApiResponse();
                jsonResponse.ErrorCode = "99";
                jsonResponse.ErrorDescription = ex.Message;
                jsonResponse.ServerSource = "API Server";
                objResp = jsonResponse;
            }
            return Ok(JsonConvert.SerializeObject(objResp));

        }

        [AllowAnonymous]
        [HttpPost("GetSeed")]
        public IActionResult GetSeed([FromBody] object strParameters)
        {
            
            JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());
            string strToken = jsonObj["JwtToken"].ToString();
            return Ok(JsonConvert.SerializeObject(UniversalFunctions.GetJwtTokenValue(
                    jsonObj["JwtToken"].ToString()
                    ,jsonObj["ItemKey"].ToString())));
        }

        [AllowAnonymous]
        [HttpPost("SaveB64")]
        public IActionResult SaveB64([FromBody] object strParameters)
        {

            ApiResponse jsonResponse = new ApiResponse();
            try
            {
                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());
                DataTable dt = UniversalFunctions.TableFromMSSQL("SaveDocuments", "UserParams", JsonConvert.SerializeObject(jsonObj));
                jsonResponse = UniversalFunctions.DatatableToJson(dt, "0", "Successful");

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


        [AllowAnonymous]
        [HttpPost("AddMenu")]
        public IActionResult AddMenu([FromBody] object strParameters)
        {

            ApiResponse jsonResponse = new ApiResponse();
            try
            {
                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());
                DataTable dt = UniversalFunctions.TableFromMSSQL("AddMenu", "UserParams", JsonConvert.SerializeObject(jsonObj));
                jsonResponse = UniversalFunctions.DatatableToJson(dt, "0", "Successful");

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


        [AllowAnonymous]
        [HttpPost("GetRefDetails")]
        public IActionResult Refdetails([FromBody] object strParameters)
        {

            ApiResponse jsonResponse = new ApiResponse();
            try
            {
                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());
                DataTable dt = UniversalFunctions.TableFromMSSQL("GetRefDetails", "UserParams", JsonConvert.SerializeObject(jsonObj));
                jsonResponse = UniversalFunctions.DatatableToJson(dt, "0", "Successful");

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

        [AllowAnonymous]
        [HttpPost("GroupAssign")]
        public IActionResult GroupAssign([FromBody] object strParameters)
        {

            ApiResponse jsonResponse = new ApiResponse();
            try
            {
                JObject jsonObj = (JObject)JsonConvert.DeserializeObject(strParameters.ToString());
                DataTable dt = UniversalFunctions.TableFromMSSQL("GroupAssign", "UserParams", JsonConvert.SerializeObject(jsonObj));
                jsonResponse = UniversalFunctions.DatatableToJson(dt, "0", "Successful");

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
