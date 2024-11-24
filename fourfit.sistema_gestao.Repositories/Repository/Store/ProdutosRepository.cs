using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Store
{
    public class ProdutosRepository : BaseRepository<Produtos>, IProdutosServices
    {
        private readonly DataContext _dataContext;

        public ProdutosRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<Produtos>> ObterProdutosExistentes()

        {

            var resultado = await _dataContext.Set<Produtos>()
                .Include(x => x.Categorias)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<Produtos> ObterProdutosPorId(int Id)
        {
            var resultado = await _dataContext.Set<Produtos>()
                .Include(x => x.Categorias).Where(x => x.Id == Id)
                .FirstOrDefaultAsync();



            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }
    }
}
