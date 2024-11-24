using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IPersonalRecordServices : IBaseServices<PersonalRecord>
    {
        Task<IEnumerable<PersonalRecord>> ObterPersonalRecordExistentes();

        Task<PersonalRecord> ObterPersonalRecordPorId(int Id);
    }
}
