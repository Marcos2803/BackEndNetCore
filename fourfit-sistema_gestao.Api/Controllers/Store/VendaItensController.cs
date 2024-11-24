using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Venda;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using fourfit_sistema_gestao.Api.Validation;

namespace fourfit_sistema_gestao.Api.Controllers.Store
{
    [Route("api/[controller]")]
    [ApiController]
    public class VendaItensController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public VendaItensController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Item cadastrado com sucesso", Type = typeof(VendaItensViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(VendaItensViewModels))]
        public async Task<IActionResult> Register(VendaItensViewModels model)
        {
            try
            {
                var vendaitens = new VendaItens
                {
                    ProdutosId = model.ProdutosId,
                    Quantidade = model.Quantidade,

                };

                await _unitOfWork.VendaItensServices.Cadastro(vendaitens);
                await _unitOfWork.VendaItensServices.Salvar();
                return Ok($"Item adicionado com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Item excluído com sucesso")]
        [SwaggerResponse(404, "Item não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var venda = await _unitOfWork.VendasServices.ObterPorId(id);
                if (venda == null)
                {
                    return NotFound("Item não encontrado");
                }

                await _unitOfWork.VendaItensServices.Deletar(id);
                await _unitOfWork.VendaItensServices.Salvar();

                return Ok("Item excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
