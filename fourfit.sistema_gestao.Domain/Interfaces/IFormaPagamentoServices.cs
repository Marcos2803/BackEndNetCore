using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IFormaPagamentoServices:IBaseServices<FormaPagamento>
    {
        Task<IEnumerable<FormaPagamento>> ObterFormaPagamentoExistentes();

        Task<FormaPagamento> ObterFormaPagamentoPorId(int? Id);
    }
}
