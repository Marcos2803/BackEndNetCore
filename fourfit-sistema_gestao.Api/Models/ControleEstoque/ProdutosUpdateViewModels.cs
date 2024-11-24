namespace fourfit_sistema_gestao.Api.Models.ControleEstoque
{
    public class ProdutosUpdateViewModels
    {
        public int Id { get; set; }
        public int CategoriasId { get; set; }
        public string NomeProduto { get; set; }
        public decimal PrecoCusto { get; set; }
        public decimal PrecoVenda { get; set; }
        public int QuantidadeEstoque { get; set; }
        public int EstoqueMinimo { get; set; }
    }
}
