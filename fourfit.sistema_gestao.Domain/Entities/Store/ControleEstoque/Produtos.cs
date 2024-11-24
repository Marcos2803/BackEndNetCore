using fourfit.sistema_gestao.Domain.Entities.Store.Venda;


namespace fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque
{
    public class Produtos
    {
        public int Id { get; set; }
        public int CategoriasId { get; set; }
        public Categorias Categorias { get; set; }
        public string NomeProduto { get; set; }
        public decimal PrecoCusto { get; set; }
        public decimal PrecoVenda { get; set; }
        public int QuantidadeEstoque { get; set; }
        public int EstoqueMinimo { get; set; }

        public ICollection<VendaItens> VendaItens { get; set; }

    }
}
