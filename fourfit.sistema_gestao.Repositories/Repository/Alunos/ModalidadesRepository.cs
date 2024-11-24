using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Alunos
{
    public class ModalidadesRepository : BaseRepository<Modalidades>, IModalidadesServices
    {
        private readonly DataContext _dataContext;

        public ModalidadesRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<Modalidades>> ObterModalidadesExistentes()
        {

            var resultado = await _dataContext.Set<Modalidades>()
                .Include(x => x.Horarios)
                .Include(x => x.PlanosId)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<Modalidades> ObterModalidadesUsuariosPorId(int Id)
        {
            var resultado = await _dataContext.Set<Modalidades>()
                .Include(x => x.Horarios).Where(x => x.Id == Id).FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }

        public async Task<Modalidades> ObterModalidadesPorId(int Id)
        {
            return await _dataContext.Set<Modalidades>().FindAsync(Id);
        }
    }
}
