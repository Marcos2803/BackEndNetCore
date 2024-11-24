using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;


namespace fourfit.sistema_gestao.Repositories.Repository.Alunos
{
    public class AulaExperimentalRepository : BaseRepository<AulaExperimental>, IAulaExperimentalServices
    {
        private readonly DataContext _dataContext;
        public AulaExperimentalRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }
        public async Task<IEnumerable<AulaExperimental>> ObterAulaExperimentalExistentes()

        {

            var resultado = await _dataContext.Set<AulaExperimental>()
                .Include(x => x.User)
                .Include(x => x.Horarios)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<AulaExperimental> ObterAulaExperimentalPorId(int Id)
        {
            var resultado = await _dataContext.Set<AulaExperimental>()
                .Include(x => x.User).Where(x => x.Id == Id)
                .Include(x => x.Horarios).Where(x => x.Id == Id)
                .FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }


    }
}
