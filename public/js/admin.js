const delelteProduct = (btn) => {
  const prdoId = btn.parentNode.querySelector("[name=productId]").value;
  const productElement = btn.closest("article");
  fetch("/admin/product/" + prdoId, {
    method: "DELETE",
  })
    .then((result) => {
      return result.json();
    })
    .then((data) => {
      console.log(data);
      productElement.parentNode.removeChild(productElement);
    })
    .catch((err) => {
      console.log(err);
    });
};
