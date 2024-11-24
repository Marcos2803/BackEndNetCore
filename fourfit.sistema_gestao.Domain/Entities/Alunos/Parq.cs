namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class Parq
    {
        public int Id { get; set; }
        public int AlunoId { get; set; }
        public EntidadeAlunos Alunos { get; set; }
        public bool ProblemaCardiaco { get; set; }
        public bool DorNoPeitoAoSeExercitar { get; set; }
        public bool DesmaiaOuSenteTontura { get; set; }
        public bool ProblemaOssosOuArticulacoes { get; set; }
        public bool TomaMedicamentosPressaoCardiaco { get; set; }
        public bool MotivoFisicoOuDeSaude { get; set; }
        public DateTime DataPreenchimento { get; set; }

    }
}
