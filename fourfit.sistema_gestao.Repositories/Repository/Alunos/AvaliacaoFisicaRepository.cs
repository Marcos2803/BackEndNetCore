using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Alunos
{
    public class AvaliacaoFisicaRepository : BaseRepository<AvaliacaoFisica>, IAvaliacaoFisicaServices
    {
        private readonly DataContext _dataContext;

        public AvaliacaoFisicaRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }
        public async Task<IEnumerable<AvaliacaoFisica>> ObterAvaliacaoExistentes()
        {

            var resultado = await _dataContext.Set<AvaliacaoFisica>()
                .Include(x => x.AlunosId)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }
        public async Task<AvaliacaoFisica> ObterAvaliacaoPorId(int Id)
        {
            var resultado = await _dataContext.Set<AvaliacaoFisica>()
                .Include(x => x.Alunos).Where(x => x.Id == Id).FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }
    }
}
