using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using EbiApi.Model;

namespace EbiApi
{
    public interface IJwtTokenManager
    {
        //string Authenticate(string userName, string password);
        ApiResponse Authenticate(UserCredential credential);
    }
}
