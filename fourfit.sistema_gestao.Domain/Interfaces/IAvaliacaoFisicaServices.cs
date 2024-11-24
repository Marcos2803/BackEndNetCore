using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;


namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IAvaliacaoFisicaServices : IBaseServices<AvaliacaoFisica>
    {
        Task<IEnumerable<AvaliacaoFisica>> ObterAvaliacaoExistentes();

        Task<AvaliacaoFisica> ObterAvaliacaoPorId(int Id);
    }
}
