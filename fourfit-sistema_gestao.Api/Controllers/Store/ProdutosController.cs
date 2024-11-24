using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.ControleEstoque;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using fourfit_sistema_gestao.Api.Validation;


namespace fourfit_sistema_gestao.Api.Controllers.Store
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProdutosController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public ProdutosController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Produto cadastrado com sucesso", Type = typeof(ProdutosViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(ProdutosViewModels))]
        public async Task<IActionResult> Register(ProdutosViewModels model)
        {
            try
            {
                var categoria = await _unitOfWork.CategoriasServices.ObterPorId(model.CategoriasId);
                if (categoria == null)
                {
                    return NotFound("Categoria não encontrada");
                }
                var produtos = new Produtos
                {
                    Id = model.Id,
                    CategoriasId = model.CategoriasId,
                    NomeProduto= model.NomeProduto,
                    PrecoCusto = model.PrecoCusto,
                    PrecoVenda = model.PrecoVenda,
                    QuantidadeEstoque = model.QuantidadeEstoque,
                    EstoqueMinimo = model.EstoqueMinimo,

                };

                await _unitOfWork.ProdutosServices.Cadastro(produtos);
                await _unitOfWork.ProdutosServices.Salvar();
                return Ok($"Produto cadastrado com sucesso");
            }
            catch (Exception ex)
            {

                return StatusCode(500, "Erro interno: " + ex.Message);
            }

        }

        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações do produto obtidas com sucesso", typeof(ProdutosUpdateViewModels))]
        [SwaggerResponse(404, "produto não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var produtos = await _unitOfWork.ProdutosServices.ObterProdutosPorId(id);

            if (produtos == null)
            {
                return NotFound("Produto não encontrado");
            }

            var produtosView = new ProdutosUpdateViewModels
            {
                Id = produtos.Id,
                CategoriasId = produtos.CategoriasId,
                NomeProduto = produtos.NomeProduto,
                PrecoCusto = produtos.PrecoCusto,
                PrecoVenda = produtos.PrecoVenda,
                QuantidadeEstoque = produtos.QuantidadeEstoque,
                EstoqueMinimo = produtos.EstoqueMinimo,

            };

            return Ok(produtosView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Produto atualizado com sucesso", Type = typeof(ProdutosUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Produto não encontrado", Type = typeof(ProdutosUpdateViewModels))]
        public async Task<IActionResult> Update(ProdutosUpdateViewModels model)
        {
            try
            {

                var produtos = await _unitOfWork.ProdutosServices.ObterPorId(model.Id);
                if (produtos == null)
                {
                    return NotFound("Produto não encontrado");
                }

                produtos.NomeProduto = model.NomeProduto;
                produtos.CategoriasId = model.CategoriasId;
                produtos.PrecoCusto = model.PrecoCusto;
                produtos.PrecoVenda = model.PrecoVenda;
                produtos.QuantidadeEstoque = model.QuantidadeEstoque;
                produtos.EstoqueMinimo = model.EstoqueMinimo;


                await _unitOfWork.ProdutosServices.Atualizar(produtos);
                await _unitOfWork.ProdutosServices.Salvar();

                return Ok($"Produto atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Produto excluído com sucesso")]
        [SwaggerResponse(404, "Produto não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var produto = await _unitOfWork.ProdutosServices.ObterPorId(id);
                if (produto == null)
                {
                    return NotFound("produto não encontrado");
                }

                await _unitOfWork.ProdutosServices.Deletar(id);
                await _unitOfWork.ProdutosServices.Salvar();

                return Ok("Produto excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
