using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Alunos;
using fourfit_sistema_gestao.Api.Models.Fornecedor;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;


namespace fourfit_sistema_gestao.Api.Controllers.Financas
{
    [Route("api/[controller]")]
    [ApiController]
    public class FornecedoresController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public FornecedoresController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Fornecedor cadastrado com sucesso", Type = typeof(FornecedoresViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(FornecedoresViewModels))]
        public async Task<IActionResult> Register(FornecedoresViewModels model)
        {
            try
            {
                var fornecedores = new Fornecedores
                {
                    Id = model.Id,
                    NomeFornecedor = model.NomeFornecedor,
                    Tipo = model.Tipo,
                    CpfCnpj = model.CpfCnpj,
                    Email = model.Email,
                    Telefone = model.Telefone,
                    Status = model.Status,
                    Observacao = model.Observacao,

                };

                await _unitOfWork.FornecedoresServices.Cadastro(fornecedores);
                await _unitOfWork.FornecedoresServices.Salvar();
                return Ok($"Fornecedor cadastrado com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }


        }
        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações do fornecedor obtidas com sucesso", typeof(FornecedoresUpdateViewModels))]
        [SwaggerResponse(404, "Fornecedor não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var fornecedores = await _unitOfWork.FornecedoresServices.ObterFornecedoresPorId(id);

            if (fornecedores == null)
            {
                return NotFound("Fornecedor não encontrado");
            }

            var fornecedoresView = new FornecedoresUpdateViewModels
            {
                Id = fornecedores.Id,
                NomeFornecedor = fornecedores.NomeFornecedor,
                Tipo = fornecedores.Tipo,
                CpfCnpj = fornecedores.CpfCnpj,
                Telefone = fornecedores.Telefone,
                Email = fornecedores.Email,
                Status = fornecedores.Status,
                Observacao = fornecedores.Observacao,


            };

            return Ok(fornecedoresView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Fornecedor atualizado com sucesso", Type = typeof(FornecedoresUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Fornecedor não encontrado", Type = typeof(FornecedoresUpdateViewModels))]
        public async Task<IActionResult> Update(FornecedoresUpdateViewModels model)
        {
            try
            {

                var fornecedores = await _unitOfWork.FornecedoresServices.ObterPorId(model.Id);
                if (fornecedores == null)
                {
                    return NotFound("Fornecedor não encontrado");
                }

                fornecedores.NomeFornecedor = model.NomeFornecedor;
                fornecedores.Tipo = model.Tipo;
                fornecedores.Email = model.Email;
                fornecedores.CpfCnpj = model.CpfCnpj;
                fornecedores.Telefone = model.Telefone;
                fornecedores.Status = model.Status;
                fornecedores.Observacao = model.Observacao;
                

                await _unitOfWork.FornecedoresServices.Atualizar(fornecedores);
                await _unitOfWork.FornecedoresServices.Salvar();

                return Ok($"Fornecedor atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Fornecedor excluído com sucesso")]
        [SwaggerResponse(404, "Fornecedor não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var aluno = await _unitOfWork.FornecedoresServices.ObterPorId(id);
                if (aluno == null)
                {
                    return NotFound("Fornecedor não encontrado");
                }

                await _unitOfWork.FornecedoresServices.Deletar(id);
                await _unitOfWork.FornecedoresServices.Salvar();

                return Ok("Fornecedor excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }

    }
}
