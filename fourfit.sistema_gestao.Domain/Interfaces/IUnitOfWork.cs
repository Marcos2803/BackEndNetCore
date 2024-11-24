
namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IUnitOfWork
    {
        IAlunosServices AlunosServices { get; }
        ITipoPlanoServices TipoPlanoServices { get; }
        IFormaPagamentoServices FormaPagamentoServices { get; }
        IUserServices UserServices { get; }
        IProfessoresServices ProfessoresServices { get; }
        IColaboradoresServices ColaboradoresServices { get; }
        ICheckinsServices CheckinsServices { get; }
        IMensalidadesServices MensalidadesServices { get; }
        IModalidadesServices ModalidadesServices { get; }
        IAvaliacaoFisicaServices AvaliacaoFisicaServices { get; }
        IDespesasServices DespesasServices { get; }
        IInvestimentosServices InvestimentosServices { get; }
        IHorariosServices HorariosServices { get; }
        IContasBancariasServices ContasBancariasServices { get; }
        IFornecedoresServices FornecedoresServices { get; }
        IPersonalRecordServices PersonalRecordServices { get; }
        IParqServices ParqServices { get; }
        IProdutosServices ProdutosServices { get; }
        IAulaExperimentalServices AulaExperimentalServices { get; }
        IImpostosServices ImpostosServices { get; }
        IVendasServices VendasServices { get; }
        IVendaItensServices VendaItensServices { get; }
        IPagamentosServices PagamentosServices { get; }
        ICategoriasServices CategoriasServices { get; }
        IEstoqueServices EstoqueServices { get; }


    }
}
