namespace fourfit.sistema_gestao.Domain.Entities.Financas
{
    public class Fornecedores
    {
        public int Id { get; set; }
        public string NomeFornecedor { get; set; }
        public string Tipo { get; set; }
        public string CpfCnpj { get; set; }
        public string Email { get; set; }
        public string? Telefone { get; set; }
        public string Status { get; set; }
        public string Observacao { get; set; }

        public ICollection<TipoDespesas> TipoDespesas { get; set; }
    }
}
