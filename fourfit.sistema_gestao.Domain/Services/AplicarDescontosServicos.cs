namespace fourfit.sistema_gestao.Domain.Services
{

    public class AplicarDescontosServicos
    {
        public decimal ValorComDesconto{get;set;}

        public AplicarDescontosServicos(decimal valorTotal, int valorPercentual)
        {
            ValorComDesconto = valorTotal * valorTotal / 100;
        }
    }
}
