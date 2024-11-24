using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Profision
{
    public class ProfessoresRepository : BaseRepository<EntidadeProfessores>, IProfessoresServices
    {
        private readonly DataContext _dataContext;

        public ProfessoresRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<EntidadeProfessores>> ObterProfessoresExistentes()


        {
            var resultado = await _dataContext.Set<EntidadeProfessores>()
                .Include(x => x.User)
                .ToListAsync();
            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<EntidadeProfessores> ObterProfessoresUsuariosPorId(int Id)
        {
            var resultado = await _dataContext.Set<EntidadeProfessores>()
                 .Include(x => x.User).Where(x => x.Id == Id).FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }

        public async Task<EntidadeProfessores> ObterProfessoresPorId(int ProfessoresId)
        {
            return await _dataContext.Set<EntidadeProfessores>().FindAsync(ProfessoresId);
        }

        public async Task<EntidadeProfessores> ObterProfessoresUserId(string userId)
        {
            var result = await _dataContext.Set<EntidadeProfessores>()
                .Include(x => x.User)
                .Where(x => x.UserId == userId)
                .FirstOrDefaultAsync();

            if (result != null)
            {
                return result;
            }
            return null;
        }

        //public async Task Remover(EntidadeProfessores professor)
        //{
        //    var professorExistente = await _dataContext.Professores.FindAsync(professor.Id);

        //    if (professorExistente != null)
        //    {
        //        _dataContext.Professores.Remove(professorExistente);
        //        await _dataContext.SaveChangesAsync();
        //    }
        //    else
        //    {
        //        throw new Exception("Professor não encontrado");
        //    }
        //}
    }
}
