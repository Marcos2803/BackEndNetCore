using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IMensalidadesServices : IBaseServices<Mensalidades>
    {
        Task<IEnumerable<Mensalidades>> ObterMensalidadesExistentes();

        Task<Mensalidades> ObterMensalidadesPorId(int Id);

        Task<Mensalidades> PossuiMensalidadeAtiva(int alunoId);

        
    }
}
