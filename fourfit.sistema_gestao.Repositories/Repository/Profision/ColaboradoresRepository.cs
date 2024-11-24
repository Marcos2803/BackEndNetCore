using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;


namespace fourfit.sistema_gestao.Repositories.Repository.Profision
{
    public class ColaboradoresRepository : BaseRepository<EntidadeColaboradores>, IColaboradoresServices
    {
        private readonly DataContext _dataContext;

        public ColaboradoresRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }
        public async Task<IEnumerable<EntidadeColaboradores>> ObterColaboradoresExistentes()
        {
            var resultado = await _dataContext.Set<EntidadeColaboradores>()
                .Include(x => x.User)
                .ToListAsync();
            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }


        public async Task<EntidadeColaboradores> ObterColaboradoresUsuariosPorId(int Id)
        {
            var resultado = await _dataContext.Set<EntidadeColaboradores>()
                .Include(x => x.User).Where(x => x.Id == Id).FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;
        }

        public async Task<EntidadeColaboradores> ObterColaboradorPorUserId(string userId)
        {
            var result = await _dataContext.Set<EntidadeColaboradores>()
                .Include(x => x.User)
                .Where(x => x.UserId == userId)
                .FirstOrDefaultAsync();

            if (result != null)
            {
                return result;
            }
            return null;
        }
    }
}
