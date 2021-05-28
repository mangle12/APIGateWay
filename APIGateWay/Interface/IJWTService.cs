using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIGateWay.Interface
{
    public interface IJWTService
    {
        string GetToken(string account);
        Guid ValidateToken(string token);

        string GetToken_1(string account);
    }
}
