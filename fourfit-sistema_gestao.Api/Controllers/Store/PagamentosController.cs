using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Pagamento;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers.Store
{
    [Route("api/[controller]")]
    [ApiController]
    public class PagamentosController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public PagamentosController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        //[HttpPost]
        //[Route("Register")]
        ////[Authorize]
        //[SwaggerResponse(statusCode: 200, description: "Pagamento cadastrado com sucesso", Type = typeof(PagamentosViewModels))]
        //[SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        //[SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        //[SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        //[SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(PagamentosViewModels))]
        //public async Task<IActionResult> Register(PagamentosViewModels model)
        //{
        //    try
        //    {
                
        //        var pagamento = new Pagamentos
        //        {
        //            Id = model.Id,
        //            DataPagamento = DateTime.Now,
        //            FormaPagamentoId = model.FormaPagamentoId,
        //            ContasBancariasId = model.ContasBancariasId,
        //            StatusPagamentos = model.StatusPagamentos,
        //            ValorVenda = model.ValorVenda,
        //            Desconto = model.Desconto,
        //            ValorComDesconto = model.ValorComDesconto,
        //            ValorPago = model.ValorPago,
        //            Troco = model.Troco,
                   

        //        };

        //        await _unitOfWork.PagamentosServices.Cadastro(pagamento);
        //        await _unitOfWork.PagamentosServices.Salvar();
        //        return Ok($"Pagamento cadastrado com sucesso");
        //    }
        //    catch (Exception ex)
        //    {

        //        throw new Exception(ex.Message);
        //    }

        //}

        //[HttpDelete]
        //[Route("Delete/{id}")]
        //[SwaggerResponse(200, "Pagamento excluído com sucesso")]
        //[SwaggerResponse(404, "Pagamento não encontrado")]
        //[SwaggerResponse(500, "Erro interno")]
        //public async Task<IActionResult> Delete(int id)
        //{
        //    try
        //    {
        //        var pagamento = await _unitOfWork.PagamentosServices.ObterPorId(id);
        //        if (pagamento == null)
        //        {
        //            return NotFound("Pagamento não encontrado");
        //        }

        //        await _unitOfWork.PagamentosServices.Deletar(id);
        //        await _unitOfWork.PagamentosServices.Salvar();

        //        return Ok("Pagamento excluído com sucesso");
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, "Erro interno: " + ex.Message);
        //    }
        //}

    }
}
