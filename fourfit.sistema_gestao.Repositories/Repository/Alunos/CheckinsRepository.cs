using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Alunos
{
    public class CheckinsRepository : BaseRepository<Checkins>, ICheckinsServices
    {
        private readonly DataContext _dataContext;

        public CheckinsRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<Checkins>> ObterCheckinExistentes()
        {
            var resultado = await _dataContext.Set<Checkins>()
                .Include(x => x.Alunos)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }
        public async Task<Checkins> ObterCheckinUsuariosPorId(int Id)
        {
            var resultado = await _dataContext.Set<Checkins>()
                .Include(x => x.Alunos).Where(x => x.Id == Id).FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;
        }
    }
}
