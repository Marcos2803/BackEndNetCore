

namespace fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque
{
    public class Categorias
    {
        public int Id { get; set; }
        public string? NomeCategoria { get; set; }


        public virtual ICollection<Produtos>? Produtos { get; set; }
    }
}
