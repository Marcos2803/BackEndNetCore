using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Account
{
    public class UserRepository : BaseRepository<User>, IUserServices
    {
        private readonly DataContext _dataContext;

        public UserRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<User> ObterPorUserId(string UserId)
        {
            return await _dataContext.Set<User>().FindAsync(UserId);

        }
        public async Task<IEnumerable<User>> ObterUsuariosComEmailConfirmado()
        {
            return await _dataContext.Usuarios.Where(x => x.EmailConfirmed).ToListAsync();
        }

        public async Task<IEnumerable<User>> ObterUsuariosMensalidades()

        {

            var resultado = await _dataContext.Set<User>()
                .Include(x => x.Alunos)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        //Task<IEnumerable<User>> IUserServices.ObterUsuariosMensalidades()
        //{
        //    throw new NotImplementedException();
        //}
    }
}
