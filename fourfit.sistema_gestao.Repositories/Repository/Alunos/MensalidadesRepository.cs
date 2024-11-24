using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Enumerables;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Alunos
{
    public class MensalidadesRepository : BaseRepository<Mensalidades>, IMensalidadesServices
    {
        private readonly DataContext _dataContext;
        public MensalidadesRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<Mensalidades>> ObterMensalidadesExistentes()
        {

            var resultado = await _dataContext.Set<Mensalidades>()
                .Include(x => x.AlunosId)
                .Include(x => x.PlanoId)
                .Include(x => x.ContasBancariasId)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<Mensalidades> ObterMensalidadesPorId(int Id)
        {
            var resultado = await _dataContext.Set<Mensalidades>()
                .Include(x => x.AlunosId).Where(x => x.Id == Id)
                .Include(x => x.PlanoId).Where(x => x.Id == Id)
                .Include(x => x.ContasBancariasId).Where(x => x.Id == Id)
                .FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }


        public async Task<Mensalidades> PossuiMensalidadeAtiva(int alunoId)
        {
            var result = await _dataContext.Set<Mensalidades>()
                .Include(x => x.Alunos)
                .Where(x => x.AlunosId == alunoId && x.StatusMensalidades == StatusMensalidadesEnum.Ativo)
                .FirstOrDefaultAsync();

            if (result != null)
            {
                return result;
            }
            return null;
        }

        
    }

}
