
namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class AvaliacaoFisica
    {
        public int Id { get; set; }
        public int AlunosId { get; set; }
        public EntidadeAlunos Alunos { get; set; }
        public DateTime DataAvaliacao { get; set; }
        public int Idade { get; set; }
        public decimal Altura { get; set; }
        public decimal Peso { get; set; }
        public decimal PercentualGordura { get; set; }
        public decimal? MassaMagra { get; set; }
        public decimal? TaxaMetabolica { get; set; }
        public decimal? GorduraVisceral { get; set; }
        public decimal? Imc { get; set; }
        public int? IdadeCorporal { get; set; }
        public decimal? BicepsRelaxadoD { get; set; }
        public decimal? BicepsRelaxadoE { get; set; }
        public decimal? BicepsContraidoD { get; set; }
        public decimal? BicepsContraidoE { get; set; }
        public decimal? AntebracoD { get; set; }
        public decimal? AntebracoE { get; set; }
        public decimal? Costa { get; set; }
        public decimal? Peitoral { get; set; }
        public decimal? Cintura { get; set; }
        public decimal? Abdomen { get; set; }
        public decimal? Quadril { get; set; }
        public decimal? CoxaD { get; set; }
        public decimal? CoxaE { get; set; }
        public decimal? PanturrilhaD { get; set; }
        public decimal? PanturrilhaE { get; set; }
    }
}
