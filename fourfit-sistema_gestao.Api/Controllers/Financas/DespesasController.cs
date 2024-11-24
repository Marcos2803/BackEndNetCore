using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Despesa;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers.Financas
{
    [Route("api/[controller]")]
    [ApiController]
    public class DespesasController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public DespesasController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Despesas cadastrado com sucesso", Type = typeof(DespesasViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(DespesasViewModels))]
        public async Task<IActionResult> Register(DespesasViewModels model)
        {
            try
            {
                var despesas = new Despesas
                {
                    Id = model.Id,
                    FormaPagamentoId = model.FormaPagamentoId,
                    ContasBancariasId = model.ContasBancariasId,
                    TipoDespesasId = model.TipoDespesasId,
                    Descricao = model.Descricao,
                    ValorDespesa = model.ValorDespesa,
                    DataVencimento = model.DataVencimento,
                    DataPagamento = model.DataPagamento,
                    StatusPagamentos = model.StatusPagamentos,
                    Observacao = model.Observacao,
                    

                };

                await _unitOfWork.DespesasServices.Cadastro(despesas);
                await _unitOfWork.DespesasServices.Salvar();
                return Ok($"Despesa cadastrada com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Despesa excluído com sucesso")]
        [SwaggerResponse(404, "Despesa não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var despesa = await _unitOfWork.DespesasServices.ObterPorId(id);
                if (despesa == null)
                {
                    return NotFound("Despesa não encontrado");
                }

                await _unitOfWork.DespesasServices.Deletar(id);
                await _unitOfWork.DespesasServices.Salvar();

                return Ok("Despesa excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
