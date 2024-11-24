using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;


namespace fourfit.sistema_gestao.Repositories.Repository.Store
{
    public class VendaItensRepository : BaseRepository<VendaItens>, IVendaItensServices
    {
        private readonly DataContext _dataContext;
        public VendaItensRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<VendaItens>> ObterIntensExistentes()

        {

            var resultado = await _dataContext.Set<VendaItens>()
                .Include(x => x.Produtos)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<VendaItens> ObterItensPorId(int Id)
        {
            var resultado = await _dataContext.Set<VendaItens>()
                .Include(x => x.Produtos).Where(x => x.Id == Id)
                .FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }
        public async Task<decimal> CalcularValorTotal(IEnumerable<VendaItens> itens)
        {
            decimal valorTotal = 0;
            foreach (var item in itens)
            {
                valorTotal += item.Produtos.PrecoVenda * item.Quantidade;
            }
            return valorTotal;
        }
    }
}
