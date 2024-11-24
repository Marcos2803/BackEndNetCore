using fourfit.sistema_gestao.Domain.Entities.Account;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IAuthenticationJwtServices
    {
        string CreateToken(User user);
    }
}
