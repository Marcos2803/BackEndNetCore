using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IUserServices:IBaseServices<User>
    {
        Task<User> ObterPorUserId(string UserId);
        Task<IEnumerable<User>> ObterUsuariosComEmailConfirmado();
        Task<IEnumerable<User>> ObterUsuariosMensalidades();


    }
}
