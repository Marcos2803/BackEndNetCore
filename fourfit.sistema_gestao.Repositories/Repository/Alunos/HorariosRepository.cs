using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;


namespace fourfit.sistema_gestao.Repositories.Repository.Alunos
{
    public class HorariosRepository : BaseRepository<Horarios>, IHorariosServices
    {
        private readonly DataContext _dataContext;

        public HorariosRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<Horarios>> ObterHorariosExistentes()

        {

            var resultado = await _dataContext.Set<Horarios>()
                .Include(x => x.ProfessoresId)
                .Include(x => x.ModalidadesId)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        //public Task<Horarios> ObterHorariosPorId(int Id)
        //{
        //    throw new NotImplementedException();
        //}

        public async Task<Horarios> ObterHorariosPorId(int Id)
        {
            var resultado = await _dataContext.Set<Horarios>()
                .Include(x => x.Professores)
                .Include(x => x.Modalidades)
                .Where(x => x.Id == Id).FirstOrDefaultAsync();



            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }

    }
}
