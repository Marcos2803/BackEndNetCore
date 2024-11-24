using fourfit.sistema_gestao.Domain.Entities.Alunos;

namespace fourfit_sistema_gestao.Api.Models.Parq
{
    public class ParqViewModels
    {
        public int Id { get; set; }
        public int AlunoId { get; set; }
        public bool ProblemaCardiaco { get; set; }
        public bool DorNoPeitoAoSeExercitar { get; set; }
        public bool DesmaiaOuSenteTontura { get; set; }
        public bool ProblemaOssosOuArticulacoes { get; set; }
        public bool TomaMedicamentosPressaoCardiaco { get; set; }
        public bool MotivoFisicoOuDeSaude { get; set; }
        public DateTime DataPreenchimento { get; set; }
    }
}
