using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EbiApi.Model
{
    public class UserCredential
    {
        public string LoginId { get; set; }
        public string Password { get; set; }
        public string UserType { get; set; }
    }

    public class ApiResponse
    {
        public string ErrorCode { get; set; }
        public string ErrorDescription { get; set; }
        public string ServerSource { get; set; } // Front API or BPB API
        public object ObjectData { get; set; }
        public object ApiCmd { get; set; }
    }

    public class JsonLog
    {
        public string TraceNo { get; set; }
        public string FileDate { get; set; }
        public string FileTime { get; set; } 
    }
}
