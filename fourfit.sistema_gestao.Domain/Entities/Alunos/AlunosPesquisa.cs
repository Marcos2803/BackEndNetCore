namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class AlunosPesquisa
    {
        public int Id { get; set; }
        public byte[] Foto { get; set; }
        public string NomeCompleto { get; set; }
        public bool Ativo { get; set; }
        public string DescTipoPlano { get; set; }
        public string Tipo { get; set; }
        public DateTime DataInicio { get; set; }
        public DateTime DataFim { get; set; }
    }
}
