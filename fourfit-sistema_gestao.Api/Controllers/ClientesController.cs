using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ClientesController : ControllerBase
    {
        [HttpGet]
        public async Task<IActionResult> ObterUsarios()
        {
            try
            {
                var lista = new List<EntidadeAlunos>();
                lista.Add(new EntidadeAlunos()
                {
                    Id = 1,
                    UserId = "teste",
                    //DataInicio = DateTime.Now,
                    
                   


                });
                lista.Add(new EntidadeAlunos()
                {
                    Id = 2,
                    UserId = "teste",
                    //DataInicio = DateTime.Now,
                    
                    


                });


                return Ok(lista.ToList());
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }
        }

    }
}
