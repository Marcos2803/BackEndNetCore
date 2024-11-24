using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;

namespace fourfit.sistema_gestao.Repositories.Repository.Financas
{
    public class FornecedoresRepository : BaseRepository<Fornecedores>, IFornecedoresServices
    {
        private readonly DataContext _dataContext;
        public FornecedoresRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public Task<IEnumerable<Fornecedores>> ObterFornecedoresExistentes()
        {
            throw new NotImplementedException();
        }

        public async Task<Fornecedores> ObterFornecedoresPorId(int Id)
        {

            return await _dataContext.Set<Fornecedores>().FindAsync(Id);
        }
    }
}
